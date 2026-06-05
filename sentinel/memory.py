"""
Memory forensics module. Detects:
  - Process hollowing indicators (on-disk vs in-memory image mismatch)
  - RWX memory regions (PAGE_EXECUTE_READWRITE, almost never legitimate)
  - Shellcode signatures inside RWX regions (NOP sleds, syscall stubs, egg hunters)
  - Unbacked executable regions (executable memory not mapped to any file)

Windows: ctypes + kernel32 (VirtualQueryEx, ReadProcessMemory).
Linux:   /proc/[pid]/maps + /proc/[pid]/mem.
"""

from __future__ import annotations

import ctypes
import logging
import os
import platform
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import psutil

log = logging.getLogger(__name__)

IS_WIN = platform.system() == "Windows"

# . . -
# Data types
# . . -

@dataclass
class MemoryFinding:
    pid: int
    name: str
    severity: str          # "info", "low", "medium", "high", "critical"
    kind: str              # "process_hollowing", "rwx_region", "shellcode", "unbacked_exec"
    detail: str
    address: Optional[int] = None
    size: Optional[int] = None


@dataclass
class MemoryReport:
    findings: list[MemoryFinding] = field(default_factory=list)
    scanned: int = 0
    errors: int = 0

    def add(self, f: MemoryFinding) -> None:
        self.findings.append(f)

    @property
    def clean(self) -> bool:
        return len(self.findings) == 0


# . . -
# Constants
# . . -

# Windows memory protection flags
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
MEM_COMMIT = 0x1000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# Shellcode byte patterns (as raw bytes for scanning)
SHELLCODE_SIGS: list[tuple[bytes, str]] = [
    (b"\x90\x90\x90\x90", "NOP sled (4+ bytes)"),
    (b"\x90\x50\x90\x50", "egg hunter marker (0x5090)"),
    (b"\x0f\x05", "syscall instruction (x86-64)"),
    (b"\xcd\x80", "int 0x80 (x86 Linux syscall)"),
    (b"\x0f\x34", "sysenter instruction"),
    # Metasploit stage markers
    (b"\xfc\xe8\x82\x00\x00\x00", "Metasploit reverse_tcp stub"),
    (b"\xfc\xe8\x89\x00\x00\x00", "Metasploit bind_tcp stub"),
    (b"\xfc\x48\x83\xe4\xf0", "Metasploit x64 stage prefix"),
    # Common shellcode prologues
    (b"\x60\x89\xe5\x31\xc0", "pushad/mov ebp,esp/xor eax,eax prologue"),
    (b"\x31\xc9\xf7\xe1", "xor ecx,ecx / mul ecx zero-register idiom"),
]

# Minimum NOP sled length to flag (short runs are common in padding)
MIN_NOP_SLED = 16

# Processes to skip (system-level, access will be denied anyway)
SKIP_PIDS: set[int] = {0, 4}

# . . -
# Windows structures for VirtualQueryEx
# . . -

if IS_WIN:
    import ctypes.wintypes

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", ctypes.wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", ctypes.wintypes.DWORD),
            ("Protect", ctypes.wintypes.DWORD),
            ("Type", ctypes.wintypes.DWORD),
        ]

    _MBI_SIZE = ctypes.sizeof(MEMORY_BASIC_INFORMATION)

    _k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

    _k32.OpenProcess.argtypes = [
        ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD,
    ]
    _k32.OpenProcess.restype = ctypes.wintypes.HANDLE

    _k32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
    _k32.CloseHandle.restype = ctypes.wintypes.BOOL

    _k32.VirtualQueryEx.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION),
        ctypes.c_size_t,
    ]
    _k32.VirtualQueryEx.restype = ctypes.c_size_t

    _k32.ReadProcessMemory.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    _k32.ReadProcessMemory.restype = ctypes.wintypes.BOOL

    def _open_process(pid: int) -> Optional[ctypes.wintypes.HANDLE]:
        """Open a process handle with query + VM read access."""
        h = _k32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid,
        )
        if not h:
            return None
        return h

    def _read_region(handle: ctypes.wintypes.HANDLE, addr: int, size: int) -> Optional[bytes]:
        """Read up to `size` bytes from process memory. Returns None on failure."""
        cap = min(size, 4096)
        buf = (ctypes.c_char * cap)()
        read = ctypes.c_size_t(0)
        ok = _k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, cap, ctypes.byref(read))
        if not ok or read.value == 0:
            return None
        return bytes(buf[: read.value])

    def _enum_regions(handle: ctypes.wintypes.HANDLE) -> list[MEMORY_BASIC_INFORMATION]:
        """Walk the virtual address space and return committed region descriptors."""
        regions: list[MEMORY_BASIC_INFORMATION] = []
        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0
        while True:
            ret = _k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), _MBI_SIZE)
            if ret == 0:
                break
            regions.append(MEMORY_BASIC_INFORMATION(
                mbi.BaseAddress, mbi.AllocationBase, mbi.AllocationProtect,
                mbi.RegionSize, mbi.State, mbi.Protect, mbi.Type,
            ))
            next_addr = (addr or 0) + mbi.RegionSize
            if next_addr <= addr:
                break
            addr = next_addr
        return regions


# . . -
# Linux: parse /proc/[pid]/maps
# . . -

@dataclass
class _LinuxRegion:
    start: int
    end: int
    perms: str       # e.g. "rwxp"
    path: str        # mapped file or empty


def _parse_proc_maps(pid: int) -> list[_LinuxRegion]:
    """Parse /proc/<pid>/maps into region descriptors."""
    maps_path = Path(f"/proc/{pid}/maps")
    regions: list[_LinuxRegion] = []
    try:
        text = maps_path.read_text(errors="replace")
    except (PermissionError, OSError):
        return regions
    for line in text.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 2:
            continue
        addr_range, perms = parts[0], parts[1]
        mapped_path = parts[5].strip() if len(parts) >= 6 else ""
        try:
            start_s, end_s = addr_range.split("-")
            start = int(start_s, 16)
            end = int(end_s, 16)
        except ValueError:
            continue
        regions.append(_LinuxRegion(start, end, perms, mapped_path))
    return regions


def _linux_read_mem(pid: int, addr: int, size: int) -> Optional[bytes]:
    """Read bytes from /proc/<pid>/mem."""
    mem_path = Path(f"/proc/{pid}/mem")
    cap = min(size, 4096)
    try:
        with open(mem_path, "rb") as f:
            f.seek(addr)
            return f.read(cap)
    except (PermissionError, OSError):
        return None


# . . -
# Shellcode scanning
# . . -

def _scan_for_shellcode(data: bytes) -> list[str]:
    """Scan a memory buffer for shellcode indicators. Returns matched labels."""
    hits: list[str] = []
    if not data:
        return hits

    # Check for long NOP sled separately (need length threshold)
    nop_run = 0
    max_nop = 0
    for b in data:
        if b == 0x90:
            nop_run += 1
            max_nop = max(max_nop, nop_run)
        else:
            nop_run = 0
    if max_nop >= MIN_NOP_SLED:
        hits.append(f"NOP sled ({max_nop} consecutive 0x90 bytes)")

    # Pattern matching
    for sig, label in SHELLCODE_SIGS:
        if sig == b"\x90\x90\x90\x90":
            continue  # handled above with length check
        if sig in data:
            hits.append(label)

    return hits


# . . -
# Windows: process hollowing detection
# . . -

def _check_hollowing_win(
    pid: int,
    name: str,
    handle: ctypes.wintypes.HANDLE,
    exe_path: Optional[str],
    report: MemoryReport,
) -> None:
    """Compare the PE header on disk with the PE header in the image base region."""
    if not exe_path or not os.path.isfile(exe_path):
        return

    # Read first 512 bytes of on-disk PE
    try:
        with open(exe_path, "rb") as f:
            disk_header = f.read(512)
    except OSError:
        return
    if len(disk_header) < 64 or disk_header[:2] != b"MZ":
        return

    # Get PE signature offset
    pe_off = struct.unpack_from("<I", disk_header, 0x3C)[0]
    if pe_off + 6 > len(disk_header):
        return

    # Find the image base region (MEM_IMAGE at the process base)
    MEMORY_BASIC_INFORMATION()
    regions = _enum_regions(handle)
    for r in regions:
        if r.State != MEM_COMMIT or r.Type != MEM_IMAGE:
            continue
        mem_data = _read_region(handle, r.BaseAddress, 512)
        if not mem_data or len(mem_data) < 64 or mem_data[:2] != b"MZ":
            continue
        # Compare PE signature and optional header
        mem_pe_off = struct.unpack_from("<I", mem_data, 0x3C)[0]
        if mem_pe_off + 6 > len(mem_data) or pe_off + 6 > len(disk_header):
            break
        disk_sig = disk_header[pe_off: pe_off + 4]
        mem_sig = mem_data[mem_pe_off: mem_pe_off + 4]
        if disk_sig != mem_sig:
            report.add(MemoryFinding(
                pid=pid, name=name, severity="critical",
                kind="process_hollowing",
                detail=(
                    f"PE signature mismatch: disk offset 0x{pe_off:x} "
                    f"vs memory offset 0x{mem_pe_off:x} at image base "
                    f"0x{r.BaseAddress:x}"
                ),
                address=r.BaseAddress, size=r.RegionSize,
            ))
            return

        # Compare optional header (entry point, image base fields)
        disk_opt = disk_header[pe_off + 4: pe_off + 28]
        mem_opt = mem_data[mem_pe_off + 4: mem_pe_off + 28]
        if disk_opt != mem_opt:
            report.add(MemoryFinding(
                pid=pid, name=name, severity="critical",
                kind="process_hollowing",
                detail=(
                    f"PE optional header mismatch between disk and memory "
                    f"at image base 0x{r.BaseAddress:x}"
                ),
                address=r.BaseAddress, size=r.RegionSize,
            ))
        return  # only check the first MZ image region


# . . -
# Core scan logic: Windows
# . . -

def _scan_process_win(pid: int, name: str, exe: Optional[str], report: MemoryReport) -> None:
    """Scan a single process on Windows using VirtualQueryEx."""
    handle = _open_process(pid)
    if handle is None:
        report.errors += 1
        return

    try:
        regions = _enum_regions(handle)
        for r in regions:
            if r.State != MEM_COMMIT:
                continue

            is_rwx = r.Protect in (PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY)
            is_exec = r.Protect in (
                PAGE_EXECUTE, PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
            )
            is_unbacked = r.Type == MEM_PRIVATE and is_exec

            # .  RWX region detection . 
            if is_rwx:
                report.add(MemoryFinding(
                    pid=pid, name=name, severity="high",
                    kind="rwx_region",
                    detail=(
                        f"RWX memory at 0x{r.BaseAddress:x}, "
                        f"size 0x{r.RegionSize:x} ({r.RegionSize} bytes), "
                        f"type={'IMAGE' if r.Type == MEM_IMAGE else 'PRIVATE' if r.Type == MEM_PRIVATE else 'MAPPED'}"
                    ),
                    address=r.BaseAddress, size=r.RegionSize,
                ))

                # .  Shellcode scan inside RWX . 
                data = _read_region(handle, r.BaseAddress, r.RegionSize)
                if data:
                    hits = _scan_for_shellcode(data)
                    for label in hits:
                        report.add(MemoryFinding(
                            pid=pid, name=name, severity="critical",
                            kind="shellcode",
                            detail=(
                                f"{label} in RWX region at 0x{r.BaseAddress:x} "
                                f"(size 0x{r.RegionSize:x})"
                            ),
                            address=r.BaseAddress, size=r.RegionSize,
                        ))

            # .  Unbacked executable region . 
            if is_unbacked:
                report.add(MemoryFinding(
                    pid=pid, name=name, severity="high",
                    kind="unbacked_exec",
                    detail=(
                        f"Private executable region at 0x{r.BaseAddress:x}, "
                        f"size 0x{r.RegionSize:x}, protect=0x{r.Protect:x}"
                    ),
                    address=r.BaseAddress, size=r.RegionSize,
                ))

        # .  Process hollowing check . 
        _check_hollowing_win(pid, name, handle, exe, report)

    finally:
        _k32.CloseHandle(handle)


# . . -
# Core scan logic: Linux
# . . -

def _scan_process_linux(pid: int, name: str, report: MemoryReport) -> None:
    """Scan a single process on Linux via /proc/[pid]/maps."""
    regions = _parse_proc_maps(pid)
    if not regions:
        report.errors += 1
        return

    for r in regions:
        is_exec = "x" in r.perms
        is_write = "w" in r.perms
        is_rwx = is_exec and is_write and "r" in r.perms
        has_backing = bool(r.path) and not r.path.startswith("[")
        size = r.end - r.start

        # .  RWX region . 
        if is_rwx:
            report.add(MemoryFinding(
                pid=pid, name=name, severity="high",
                kind="rwx_region",
                detail=(
                    f"RWX region 0x{r.start:x}-0x{r.end:x} "
                    f"(size 0x{size:x}), "
                    f"backing={'none' if not r.path else r.path}"
                ),
                address=r.start, size=size,
            ))

            # .  Shellcode scan inside RWX . 
            data = _linux_read_mem(pid, r.start, size)
            if data:
                hits = _scan_for_shellcode(data)
                for label in hits:
                    report.add(MemoryFinding(
                        pid=pid, name=name, severity="critical",
                        kind="shellcode",
                        detail=(
                            f"{label} in RWX region at 0x{r.start:x} "
                            f"(size 0x{size:x})"
                        ),
                        address=r.start, size=size,
                    ))

        # .  Unbacked executable (anonymous or heap, not [vdso]/[vsyscall]) . 
        if is_exec and not has_backing:
            # skip well-known kernel mappings
            if r.path in ("[vdso]", "[vsyscall]"):
                continue
            report.add(MemoryFinding(
                pid=pid, name=name, severity="high",
                kind="unbacked_exec",
                detail=(
                    f"Anonymous executable region 0x{r.start:x}-0x{r.end:x} "
                    f"(size 0x{size:x}), perms={r.perms}"
                ),
                address=r.start, size=size,
            ))


# . . -
# Public API
# . . -

def scan_memory(pids: Optional[list[int]] = None) -> MemoryReport:
    """Scan process memory for injection and shellcode indicators.

    Args:
        pids: specific PIDs to scan. None means scan all accessible processes.

    Returns:
        MemoryReport with findings and scan statistics.
    """
    report = MemoryReport()

    if pids is not None:
        targets = []
        for p in pids:
            try:
                targets.append(psutil.Process(p))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                report.errors += 1
    else:
        targets = list(psutil.process_iter(["pid", "name", "exe"]))

    for proc in targets:
        try:
            pid = proc.pid
            if pid in SKIP_PIDS:
                continue
            name = proc.name() or f"<pid:{pid}>"
            report.scanned += 1

            if IS_WIN:
                exe = None
                try:
                    exe = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                _scan_process_win(pid, name, exe, report)
            else:
                _scan_process_linux(pid, name, report)

        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            report.errors += 1
        except psutil.AccessDenied:
            report.errors += 1
        except Exception as exc:
            report.errors += 1
            log.debug("pid %d scan error: %s", proc.pid, exc)

    return report


def run(quick: bool = True) -> list[MemoryFinding]:
    """Entry point matching the sentinel module interface.

    Args:
        quick: if True, skip the full scan (reserved for future tuning).

    Returns:
        list of Finding objects from the memory scan.
    """
    report = scan_memory()
    return report.findings
