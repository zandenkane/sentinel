"""
Named pipe enumeration and anomaly detection.
Windows: enumerate pipes via os.listdir on \\\\.\\pipe\\, match C2 signatures,
flag high-entropy / UUID names, check for unsigned owning processes.
Linux: check /tmp/.X11-unix and abstract sockets for anomalies.
"""
from __future__ import annotations

import logging
import math
import os
import platform
import re
import sys
from dataclasses import dataclass, field
from typing import Optional

import psutil

IS_WIN = platform.system() == "Windows"
log = logging.getLogger(__name__)


@dataclass
class PipeFinding:
    pipe_name: str
    kind: str   # c2_pattern | high_entropy | uuid_name | unsigned_owner | abstract_socket
    detail: str
    pid: Optional[int] = None
    process_name: Optional[str] = None


@dataclass
class PipeReport:
    findings: list[PipeFinding] = field(default_factory=list)
    pipes_scanned: int = 0
    errors: int = 0

    def add(self, f: PipeFinding) -> None:
        self.findings.append(f)

    @property
    def clean(self) -> bool:
        return len(self.findings) == 0


# .  C2 pipe patterns . . 
C2_PIPE_PATTERNS: list[tuple[str, str]] = [
    (r"msagent_",       "Cobalt Strike msagent"),
    (r"MSSE-",          "Cobalt Strike MSSE"),
    (r"postex_",        "Cobalt Strike postex"),
    (r"status_",        "Cobalt Strike status"),
    (r"postex_ssh_",    "Cobalt Strike SSH"),
    (r"demoagent_",     "Cobalt Strike demo"),
    (r"meterpreter",    "Meterpreter"),
    (r"met[_.]",        "Meterpreter variant"),
    (r"sliver",         "Sliver C2"),
    (r"havoc",          "Havoc C2"),
    (r"demon",          "Havoc demon"),
    (r"poshc2",         "PoshC2"),
    (r"psexec",         "PsExec lateral movement"),
    (r"cobaltstrike",   "Cobalt Strike explicit"),
    (r"beacon",         "Generic beacon"),
]
_C2_RX = [(re.compile(p, re.IGNORECASE), d) for p, d in C2_PIPE_PATTERNS]

# .  Known-good pipe prefixes (Windows) .  suppress false positives . 
_GOOD_PREFIXES: list[str] = [
    "lsass", "wkssvc", "srvsvc", "browser", "ntsvcs", "winreg",
    "spoolss", "epmapper", "samr", "netlogon", "svcctl", "atsvc",
    "eventlog", "InitShutdown", "LSM_API_service", "trkwks",
    "plugplay", "protected_storage", "scerpc", "W32TIME_ALT",
    "crashpad_", "chrome.", "mojo.", "discord-ipc-",
    "dotnet-diagnostic-", "vscode-", "PSHost.", "PowerShell",
    "Winsock2\\", "winsock2\\", "LOCAL\\", "TSVCPIPE-",
    "git-lfs-", "winpty-", "conhost-", "docker_engine",
    "gecko-crash-server-pipe", "openssh-ssh-agent",
    "SQLLocal\\", "MSSQL$", "MsQuic", "DAV RPC SERVICE",
]

_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I,
)
_HEX_BLOCK_RE = re.compile(r"[0-9a-f]{16,}", re.I)
ENTROPY_THRESHOLD = 3.8


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _is_known_good(name: str) -> bool:
    low = name.lower()
    for prefix in _GOOD_PREFIXES:
        if low.startswith(prefix.lower()):
            return True
    return False


def _match_c2(name: str) -> Optional[str]:
    for rx, desc in _C2_RX:
        if rx.search(name):
            return desc
    return None


# .  Windows enumeration . . -
def _enumerate_pipes_win() -> list[str]:
    try:
        return os.listdir(r"\\.\pipe\\")
    except OSError as exc:
        log.warning("pipe enumeration failed: %s", exc)
        return []


def _find_pipe_owner(pipe_name: str) -> Optional[int]:
    target = pipe_name.lower()
    for proc in psutil.process_iter(["pid"]):
        try:
            for fobj in proc.open_files():
                if fobj.path and target in fobj.path.lower():
                    return proc.pid
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            continue
    return None


def _is_signed(pid: int) -> bool:
    try:
        exe = psutil.Process(pid).exe()
        if not exe or not os.path.isfile(exe):
            return False
        from sentinel.process import is_signed
        return is_signed(exe)
    except Exception:
        return False


# .  Linux checks . . 
def _check_x11_unix() -> list[PipeFinding]:
    findings: list[PipeFinding] = []
    x11 = "/tmp/.X11-unix"
    if not os.path.isdir(x11):
        return findings
    try:
        entries = os.listdir(x11)
    except PermissionError:
        return findings
    import stat
    for e in entries:
        full = os.path.join(x11, e)
        if not re.match(r"^X\d+$", e):
            findings.append(PipeFinding(full, "abstract_socket",
                                    f"unexpected entry in /tmp/.X11-unix: {e}"))
        else:
            try:
                if not stat.S_ISSOCK(os.stat(full).st_mode):
                    findings.append(PipeFinding(full, "abstract_socket",
                                            "X11 entry is not a socket"))
            except OSError:
                pass
    return findings


def _check_abstract_sockets() -> list[PipeFinding]:
    findings: list[PipeFinding] = []
    if not os.path.isfile("/proc/net/unix"):
        return findings
    try:
        lines = open("/proc/net/unix").readlines()[1:]
    except PermissionError:
        return findings
    for line in lines:
        parts = line.strip().split()
        path = parts[-1] if len(parts) >= 8 else ""
        if not path.startswith("@"):
            continue
        name = path[1:]
        c2 = _match_c2(name)
        if c2:
            findings.append(PipeFinding(path, "c2_pattern",
                                    f"abstract socket matches: {c2}"))
        elif _shannon(name) > ENTROPY_THRESHOLD and len(name) > 8:
            findings.append(PipeFinding(path, "high_entropy",
                                    f"high-entropy abstract socket ({_shannon(name):.2f})"))
    return findings


# .  Main scan . . -
def scan_pipes() -> PipeReport:
    report = PipeReport()

    if IS_WIN:
        pipes = _enumerate_pipes_win()
        report.pipes_scanned = len(pipes)
        for name in pipes:
            if _is_known_good(name):
                continue
            c2 = _match_c2(name)
            if c2:
                report.add(PipeFinding(name, "c2_pattern", f"C2 pattern: {c2}"))
                continue
            if _UUID_RE.search(name):
                report.add(PipeFinding(name, "uuid_name",
                                   "pipe name contains UUID, possibly generated"))
                continue
            ent = _shannon(name)
            if ent > ENTROPY_THRESHOLD and len(name) > 10:
                if _HEX_BLOCK_RE.search(name) or ent > 4.0:
                    report.add(PipeFinding(name, "high_entropy",
                                       f"random-looking name (entropy={ent:.2f})"))
        # Check owners of flagged pipes
        for f in list(report.findings):
            pid = _find_pipe_owner(f.pipe_name)
            if pid is None:
                continue
            f.pid = pid
            try:
                f.process_name = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            if not _is_signed(pid):
                report.add(PipeFinding(f.pipe_name, "unsigned_owner",
                                   f"owned by unsigned process (PID {pid})",
                                   pid=pid, process_name=f.process_name))
    else:
        x11 = _check_x11_unix()
        abstract = _check_abstract_sockets()
        report.pipes_scanned = len(x11) + len(abstract)
        for f in x11 + abstract:
            report.add(f)

    return report


# .  CLI . . . -
def print_report(report: PipeReport) -> None:
    print(f"\nNamed Pipe Scan  ({report.pipes_scanned} pipes)")
    if report.clean:
        print("  CLEAN\n")
        return
    print(f"  {len(report.findings)} findings\n")
    labels = {"c2_pattern": "C2 matches", "high_entropy": "High-entropy names",
              "uuid_name": "UUID-format names", "unsigned_owner": "Unsigned owners",
              "abstract_socket": "Suspicious sockets"}
    by_kind: dict[str, list[PipeFinding]] = {}
    for f in report.findings:
        by_kind.setdefault(f.kind, []).append(f)
    for kind, items in by_kind.items():
        print(f"[!] {labels.get(kind, kind)} ({len(items)})")
        for f in items:
            tag = f" (PID {f.pid}, {f.process_name or '?'})" if f.pid else ""
            print(f"    {f.pipe_name}{tag}")
            print(f"      {f.detail}")
        print()


def main() -> None:
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    ap = argparse.ArgumentParser(description="Named pipe anomaly scanner")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)
    report = scan_pipes()
    print_report(report)
    sys.exit(0 if report.clean else 1)


if __name__ == "__main__":
    main()
