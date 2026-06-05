"""
Process integrity checks .  signature verification, suspicious paths,
known RAT names, hidden/orphaned processes, DLL injection indicators.
Windows primary, Linux secondary.

"""

from __future__ import annotations

import ctypes
import os
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import psutil

# . . . -
# Known RAT / backdoor process names (lowercase)
# . . . -
RAT_NAMES: set[str] = {
    "darkcomet", "njrat", "nanocore", "quasarrat", "asyncrat",
    "remcos", "orcus", "limerat", "revenge-rat", "adwind",
    "poisonivy", "gh0st", "blackshades", "cybergate", "xtreme",
    "spynet", "luminosity", "imminent", "warzone", "dcrat",
    "venom", "havoc", "cobalt", "beacon", "meterpreter",
    "pupy", "empire", "covenant", "sliver", "brute",
    "netbus", "subseven", "sub7", "back_orifice", "bo2k",
    "xtremerat", "xpertrat", "pandorat", "babylon",
}

# Suspicious path fragments (lowercase, forward-slash normalized)
SUSPECT_PATH_PARTS: list[str] = [
    "/temp/", "/tmp/", "/appdata/local/temp",
    "/appdata/roaming/", "/public/",
    "/users/default/", "/windows/debug/",
    "/recycle", "/$recycle",
]

# Extra suspect fragments only for DLL injection checks (more aggressive)
DLL_SUSPECT_PARTS: list[str] = [
    "/temp/", "/tmp/", "/appdata/local/temp",
    "/dev/shm/", "/users/default/", "/windows/debug/",
]

IS_WIN = platform.system() == "Windows"


# . . . -
# Data classes
# . . . -
@dataclass
class Finding:
    pid: int
    name: str
    exe: Optional[str]
    kind: str          # "unsigned", "suspect_path", "rat_name", "hidden", "dll_inject"
    detail: str


@dataclass
class ProcessReport:
    findings: list[Finding] = field(default_factory=list)
    scanned: int = 0
    errors: int = 0

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    @property
    def clean(self) -> bool:
        return len(self.findings) == 0


# . . . -
# Windows: Authenticode signature check via WinVerifyTrust
# . . . -
if IS_WIN:
    import ctypes.wintypes

    # {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
    WTD_UI_NONE = 2
    WTD_CHOICE_FILE = 1
    WTD_REVOKE_NONE = 0
    WTD_STATEACTION_VERIFY = 1

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", ctypes.c_ulong),
            ("Data2", ctypes.c_ushort),
            ("Data3", ctypes.c_ushort),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID()
    WINTRUST_ACTION_GENERIC_VERIFY_V2.Data1 = 0x00AAC56B
    WINTRUST_ACTION_GENERIC_VERIFY_V2.Data2 = 0xCD44
    WINTRUST_ACTION_GENERIC_VERIFY_V2.Data3 = 0x11D0
    WINTRUST_ACTION_GENERIC_VERIFY_V2.Data4[:] = [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", ctypes.wintypes.DWORD),
            ("pcwszFilePath", ctypes.c_wchar_p),
            ("hFile", ctypes.wintypes.HANDLE),
            ("pgKnownSubject", ctypes.c_void_p),
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", ctypes.wintypes.DWORD),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", ctypes.wintypes.DWORD),
            ("fdwRevocationChecks", ctypes.wintypes.DWORD),
            ("dwUnionChoice", ctypes.wintypes.DWORD),
            ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction", ctypes.wintypes.DWORD),
            ("hWVTStateData", ctypes.wintypes.HANDLE),
            ("pwszURLReference", ctypes.c_wchar_p),
            ("dwProvFlags", ctypes.wintypes.DWORD),
            ("dwUIContext", ctypes.wintypes.DWORD),
            ("pSignatureSettings", ctypes.c_void_p),
        ]

    TRUST_E_NOSIGNATURE = 0x800B0100

    # Set up wintrust and kernel32 function signatures once
    _wt = ctypes.windll.wintrust  # type: ignore[attr-defined]
    _k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

    _wt.CryptCATAdminAcquireContext.argtypes = [
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.wintypes.DWORD,
    ]
    _wt.CryptCATAdminAcquireContext.restype = ctypes.wintypes.BOOL

    _wt.CryptCATAdminCalcHashFromFileHandle.argtypes = [
        ctypes.wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.DWORD),
        ctypes.POINTER(ctypes.c_byte), ctypes.wintypes.DWORD,
    ]
    _wt.CryptCATAdminCalcHashFromFileHandle.restype = ctypes.wintypes.BOOL

    _wt.CryptCATAdminEnumCatalogFromHash.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_byte),
        ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.c_void_p,
    ]
    _wt.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p

    _wt.CryptCATAdminReleaseCatalogContext.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.wintypes.DWORD,
    ]
    _wt.CryptCATAdminReleaseCatalogContext.restype = ctypes.wintypes.BOOL

    _wt.CryptCATAdminReleaseContext.argtypes = [
        ctypes.c_void_p, ctypes.wintypes.DWORD,
    ]
    _wt.CryptCATAdminReleaseContext.restype = ctypes.wintypes.BOOL

    _k32.CreateFileW.argtypes = [
        ctypes.c_wchar_p, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
        ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
        ctypes.wintypes.HANDLE,
    ]
    _k32.CreateFileW.restype = ctypes.wintypes.HANDLE

    _GENERIC_READ = 0x80000000
    _FILE_SHARE_READ = 1
    _OPEN_EXISTING = 3
    _INVALID_HANDLE = ctypes.wintypes.HANDLE(-1).value

    def _win_verify_embedded(filepath: str) -> int:
        """Check embedded Authenticode. Returns raw HRESULT."""
        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = filepath
        file_info.hFile = None
        file_info.pgKnownSubject = None

        trust_data = WINTRUST_DATA()
        trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        trust_data.pPolicyCallbackData = None
        trust_data.pSIPClientData = None
        trust_data.dwUIChoice = WTD_UI_NONE
        trust_data.fdwRevocationChecks = WTD_REVOKE_NONE
        trust_data.dwUnionChoice = WTD_CHOICE_FILE
        trust_data.pFile = ctypes.pointer(file_info)
        trust_data.dwStateAction = WTD_STATEACTION_VERIFY
        trust_data.hWVTStateData = None
        trust_data.pwszURLReference = None
        trust_data.dwProvFlags = 0
        trust_data.dwUIContext = 0
        trust_data.pSignatureSettings = None

        ret = _wt.WinVerifyTrust(
            None,
            ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
            ctypes.byref(trust_data),
        )
        return ret

    def _win_verify_catalog(filepath: str) -> bool:
        """Check Windows catalog signature (for OS binaries like cmd.exe)."""
        hAdmin = ctypes.c_void_p()
        if not _wt.CryptCATAdminAcquireContext(ctypes.byref(hAdmin), None, 0):
            return False

        hFile = _k32.CreateFileW(
            filepath, _GENERIC_READ, _FILE_SHARE_READ,
            None, _OPEN_EXISTING, 0, None,
        )
        if hFile == _INVALID_HANDLE:
            _wt.CryptCATAdminReleaseContext(hAdmin, 0)
            return False

        try:
            # Get required hash size
            cb = ctypes.wintypes.DWORD(0)
            _wt.CryptCATAdminCalcHashFromFileHandle(hFile, ctypes.byref(cb), None, 0)
            if cb.value == 0:
                return False

            # Compute hash
            buf = (ctypes.c_byte * cb.value)()
            if not _wt.CryptCATAdminCalcHashFromFileHandle(hFile, ctypes.byref(cb), buf, 0):
                return False
        finally:
            _k32.CloseHandle(hFile)

        # Search catalogs for this hash
        hCat = _wt.CryptCATAdminEnumCatalogFromHash(hAdmin, buf, cb, 0, None)
        found = hCat is not None and hCat != 0

        if found:
            _wt.CryptCATAdminReleaseCatalogContext(hAdmin, hCat, 0)

        _wt.CryptCATAdminReleaseContext(hAdmin, 0)
        return found

    def _win_verify_trust(filepath: str) -> bool:
        """Return True if the file has a valid signature (embedded or catalog)."""
        ret = _win_verify_embedded(filepath)
        if ret == 0:
            return True
        # If no embedded signature, try catalog verification
        if (ret & 0xFFFFFFFF) == TRUST_E_NOSIGNATURE:
            return _win_verify_catalog(filepath)
        return False

    def is_signed(filepath: str) -> bool:
        try:
            return _win_verify_trust(filepath)
        except Exception:
            return False

else:
    def is_signed(filepath: str) -> bool:
        """On Linux, check for a basic ELF embedded signature section."""
        try:
            with open(filepath, "rb") as f:
                magic = f.read(4)
                if magic != b"\x7fELF":
                    return True  # not an ELF .  skip
                # Seek to section header offset in ELF header
                f.seek(0)
                hdr = f.read(64)
                if len(hdr) < 64:
                    return True
                # Check for .note.gnu.build-id or codesign sections
                # by scanning raw bytes .  rough heuristic
                f.seek(0)
                blob = f.read(min(os.path.getsize(filepath), 4 * 1024 * 1024))
                # Look for common signing markers
                if b"Signature" in blob or b".note.gnu.build-id" in blob:
                    return True
            return False
        except Exception:
            return False  # unreadable, treat as unverified -> skip


# . . . -
# Suspicious-path check
# . . . -
def is_suspect_path(exe_path: str) -> tuple[bool, str]:
    """Return (is_suspicious, matched_fragment)."""
    lower = exe_path.lower().replace("\\", "/")
    for frag in SUSPECT_PATH_PARTS:
        if frag in lower:
            return True, frag
    return False, ""


# . . . -
# RAT name matching
# . . . -
def matches_rat_name(proc_name: str) -> Optional[str]:
    lower = proc_name.lower().replace(".exe", "").replace(".bin", "")
    for rat in RAT_NAMES:
        if rat in lower:
            return rat
    return None


# . . . -
# Hidden / orphaned process detection
# . . . -
# Windows bootstrap processes that are normally orphaned (parent smss.exe exits)
_WIN_BOOTSTRAP_NAMES: set[str] = {
    "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "fontdrvhost.exe", "smss.exe",
}


def check_hidden_or_orphaned(proc: psutil.Process) -> Optional[str]:
    try:
        ppid = proc.ppid()
        if ppid and ppid != 0:
            try:
                psutil.Process(ppid)
            except psutil.NoSuchProcess:
                # Skip known Windows bootstrap orphans
                name = (proc.name() or "").lower()
                if IS_WIN and name in _WIN_BOOTSTRAP_NAMES:
                    pass
                else:
                    return f"orphaned .  parent pid {ppid} no longer exists"
    except (psutil.AccessDenied, psutil.ZombieProcess):
        pass

    if IS_WIN:
        try:
            if proc.status() == psutil.STATUS_ZOMBIE:
                return "zombie process"
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
    else:
        try:
            status = proc.status()
            if status == psutil.STATUS_ZOMBIE:
                return "zombie process"
            # Check /proc visibility
            proc_dir = Path(f"/proc/{proc.pid}")
            if not proc_dir.exists():
                return "pid exists in process table but missing from /proc"
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

    return None


# . . . -
# DLL injection indicators (Windows)
# . . . -
def check_dll_injection(proc: psutil.Process) -> list[str]:
    """Look for DLL injection red flags in a process's loaded modules."""
    flags: list[str] = []
    if not IS_WIN:
        # On Linux, check /proc/<pid>/maps for suspicious .so paths
        try:
            maps_file = Path(f"/proc/{proc.pid}/maps")
            if maps_file.exists():
                text = maps_file.read_text(errors="replace")
                for line in text.splitlines():
                    if "/tmp/" in line or "/dev/shm/" in line:
                        so_path = line.split()[-1] if line.split() else ""
                        if so_path.endswith(".so") or ".so." in so_path:
                            flags.append(f"suspicious shared lib: {so_path}")
        except (PermissionError, OSError):
            pass
        return flags

    # Windows: inspect memory mapped files
    try:
        mmaps = proc.memory_maps(grouped=False)
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        return flags

    exe_path = ""
    try:
        exe_path = (proc.exe() or "").lower()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass

    exe_dir = os.path.dirname(exe_path) if exe_path else ""
    sys32 = os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32").lower()
    syswow = os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "SysWOW64").lower()
    winsxs = os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "WinSxS").lower()

    known_dirs = {sys32, syswow, winsxs, exe_dir}

    seen: set[str] = set()
    for mmap in mmaps:
        dll_path = (mmap.path or "").lower()
        if not dll_path or not dll_path.endswith(".dll"):
            continue
        if dll_path in seen:
            continue
        seen.add(dll_path)
        dll_dir = os.path.dirname(dll_path)
        # DLL loaded from outside expected directories
        if dll_dir and dll_dir not in known_dirs:
            norm = dll_path.replace("\\", "/")
            for frag in DLL_SUSPECT_PARTS:
                if frag in norm:
                    flags.append(f"DLL from suspect path: {mmap.path} (matched {frag})")
                    break

    return flags


# . . . -
# Main scan
# . . . -
def scan_processes(
    check_signatures: bool = True,
    verbose: bool = False,
) -> ProcessReport:
    """Scan all accessible processes and return a report of findings."""
    report = ProcessReport()

    for proc in psutil.process_iter(["pid", "name", "exe", "status"]):
        report.scanned += 1
        pid = proc.info["pid"]
        name = proc.info["name"] or f"<pid:{pid}>"
        exe = proc.info["exe"]

        try:
            # .  RAT name check . 
            rat_match = matches_rat_name(name)
            if rat_match:
                report.add(Finding(pid, name, exe, "rat_name",
                                   f"matches known RAT pattern: {rat_match}"))

            # .  Suspect path check . 
            if exe:
                suspect, frag = is_suspect_path(exe)
                if suspect:
                    report.add(Finding(pid, name, exe, "suspect_path",
                                       f"running from suspicious location (matched '{frag}')"))

                # .  Signature check . 
                if check_signatures and os.path.isfile(exe):
                    if not is_signed(exe):
                        report.add(Finding(pid, name, exe, "unsigned",
                                           "binary has no valid signature"))

            # .  Hidden / orphaned . 
            reason = check_hidden_or_orphaned(proc)
            if reason:
                report.add(Finding(pid, name, exe, "hidden", reason))

            # .  DLL injection indicators . 
            dll_flags = check_dll_injection(proc)
            for flag in dll_flags:
                report.add(Finding(pid, name, exe, "dll_inject", flag))

        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            report.errors += 1
        except psutil.AccessDenied:
            report.errors += 1
        except Exception as exc:
            report.errors += 1
            if verbose:
                print(f"[!] pid {pid} ({name}): {exc}", file=sys.stderr)

    return report


# . . . -
# CLI
# . . . -
def print_report(report: ProcessReport) -> None:
    print(f"\nProcess integrity scan complete")
    print(f"  scanned : {report.scanned}")
    print(f"  findings: {len(report.findings)}")
    print(f"  errors  : {report.errors}")

    if report.clean:
        print("  status  : CLEAN\n")
        return

    print()
    by_kind: dict[str, list[Finding]] = {}
    for f in report.findings:
        by_kind.setdefault(f.kind, []).append(f)

    labels = {
        "unsigned": "Unsigned binaries",
        "suspect_path": "Suspicious execution paths",
        "rat_name": "Known RAT process names",
        "hidden": "Hidden / orphaned processes",
        "dll_inject": "DLL injection indicators",
    }

    for kind, findings in by_kind.items():
        print(f". - {labels.get(kind, kind)} ({len(findings)}) . -")
        for f in findings:
            exe_str = f.exe or "(unknown path)"
            print(f"  [{f.pid}] {f.name}")
            print(f"    exe   : {exe_str}")
            print(f"    detail: {f.detail}")
        print()


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Process integrity scanner")
    parser.add_argument("--no-sig", action="store_true",
                        help="Skip signature verification (faster)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print per-process errors to stderr")
    args = parser.parse_args()

    report = scan_processes(
        check_signatures=not args.no_sig,
        verbose=args.verbose,
    )
    print_report(report)
    sys.exit(0 if report.clean else 1)


if __name__ == "__main__":
    main()
