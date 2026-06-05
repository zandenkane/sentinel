"""
Browser credential store access detection.

Detects non-browser processes reading credential databases (Login Data,
logins.json, key4.db).  Primary indicator for credential stealers: mimikatz,
redline, raccoon, and custom tools all open these files directly.  Also flags
recently modified credential DBs and DPAPI master key access on Windows.
"""
from __future__ import annotations

import logging
import os
import platform
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import psutil

log = logging.getLogger(__name__)
IS_WIN = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"

# Chromium-family browser User Data locations (relative to platform app-data)
_CHROMIUM_BROWSERS: list[tuple[str, ...]] = [
    ("Google", "Chrome", "User Data"),
    ("Microsoft", "Edge", "User Data"),
    ("BraveSoftware", "Brave-Browser", "User Data"),
    ("Opera Software", "Opera Stable"),
]
_CHROMIUM_CRED_FILES: list[str] = ["Login Data", "Login Data-journal"]
_FIREFOX_CRED_FILES: list[str] = ["logins.json", "key4.db", "key3.db"]

_LEGIT_BROWSERS: set[str] = {
    "chrome", "msedge", "firefox", "brave", "opera", "vivaldi",
    "chromium", "iridium", "google chrome", "microsoft edge",
}

_DPAPI_PROTECT_DIR = os.path.join(
    os.environ.get("SYSTEMROOT", r"C:\Windows"),
    "System32", "Microsoft", "Protect",
)
_RECENT_THRESHOLD_SEC = 300  # 5 minutes


@dataclass
class Finding:
    kind: str          # "cred_access", "cred_modified", "dpapi_access"
    pid: int
    process_name: str
    detail: str
    cred_path: str
    severity: str = "high"


@dataclass
class CredStoreReport:
    findings: list[Finding] = field(default_factory=list)
    cred_dbs_found: int = 0
    processes_checked: int = 0
    errors: int = 0

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    @property
    def clean(self) -> bool:
        return len(self.findings) == 0


# .  path helpers . . . . 

def _home_dirs() -> list[Path]:
    root = Path(os.environ.get("SYSTEMDRIVE", "C:") + "\\Users") if IS_WIN else Path("/home")
    skip = {"Public", "Default", "Default User", "All Users"}
    homes = [e for e in root.iterdir() if e.is_dir() and e.name not in skip] if root.is_dir() else []
    cur = Path.home()
    if cur not in homes:
        homes.append(cur)
    return homes


def _app_data_base(home: Path) -> Path:
    if IS_WIN:
        return home / "AppData" / "Local"
    if IS_MAC:
        return home / "Library" / "Application Support"
    return home / ".config"


def _chromium_db_paths(home: Path) -> list[Path]:
    out: list[Path] = []
    base = _app_data_base(home)
    for parts in _CHROMIUM_BROWSERS:
        user_data = base.joinpath(*parts)
        if not user_data.is_dir():
            continue
        for profile in user_data.iterdir():
            if not profile.is_dir():
                continue
            for fname in _CHROMIUM_CRED_FILES:
                p = profile / fname
                if p.exists():
                    out.append(p)
    return out


def _firefox_db_paths(home: Path) -> list[Path]:
    if IS_WIN:
        base = home / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles"
    elif IS_MAC:
        base = home / "Library" / "Application Support" / "Firefox" / "Profiles"
    else:
        base = home / ".mozilla" / "firefox"
    if not base.is_dir():
        return []
    out: list[Path] = []
    for prof in base.iterdir():
        if not prof.is_dir():
            continue
        for fname in _FIREFOX_CRED_FILES:
            p = prof / fname
            if p.exists():
                out.append(p)
    return out


def _is_browser(name: str, exe: Optional[str]) -> bool:
    base = name.lower().replace(".exe", "")
    if base in _LEGIT_BROWSERS:
        return True
    if exe:
        low = exe.lower()
        return any(tag in low for tag in _LEGIT_BROWSERS)
    return False


def _open_files(pid: int) -> list[str]:
    try:
        return [f.path for f in psutil.Process(pid).open_files()]
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        return []


# .  detection checks . . . . 

def _check_recent_modifications(cred_paths: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    now = time.time()
    for p in cred_paths:
        try:
            age = now - p.stat().st_mtime
            if age < _RECENT_THRESHOLD_SEC:
                findings.append(Finding(
                    kind="cred_modified", pid=0, process_name="(filesystem)",
                    detail=f"Credential DB modified {int(age)}s ago",
                    cred_path=str(p), severity="medium",
                ))
        except OSError:
            pass
    return findings


def _check_dpapi_access() -> list[Finding]:
    """Flag non-lsass processes with handles to DPAPI master key files."""
    findings: list[Finding] = []
    if not IS_WIN:
        return findings
    root = Path(_DPAPI_PROTECT_DIR)
    if not root.exists():
        return findings
    mk_paths: set[str] = set()
    try:
        for dirpath, _, fnames in os.walk(root):
            for fn in fnames:
                mk_paths.add(os.path.join(dirpath, fn).lower())
    except PermissionError:
        log.debug("Cannot walk DPAPI Protect dir (access denied)")
        return findings
    if not mk_paths:
        return findings
    for proc in psutil.process_iter(["pid", "name"]):
        pname = (proc.info["name"] or "").lower()
        if pname in ("lsass.exe", "system", ""):
            continue
        try:
            for fp in _open_files(proc.info["pid"]):
                if fp.lower() in mk_paths:
                    findings.append(Finding(
                        kind="dpapi_access", pid=proc.info["pid"],
                        process_name=proc.info["name"] or "",
                        detail="Process has open handle to DPAPI master key",
                        cred_path=fp, severity="critical",
                    ))
        except Exception:
            pass
    return findings


# .  main scan . . . . -

def scan(check_dpapi: bool = True) -> CredStoreReport:
    """Scan for non-browser processes accessing browser credential stores."""
    report = CredStoreReport()

    # 1. Enumerate credential DB paths on disk
    cred_paths: list[Path] = []
    for home in _home_dirs():
        cred_paths.extend(_chromium_db_paths(home))
        cred_paths.extend(_firefox_db_paths(home))
    report.cred_dbs_found = len(cred_paths)
    log.info("Found %d credential database files", report.cred_dbs_found)
    cred_set: set[str] = {str(p).lower() for p in cred_paths}

    # 2. Check every process for open handles to credential DBs
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        report.processes_checked += 1
        pid, name, exe = proc.info["pid"], proc.info["name"] or "", proc.info["exe"]
        if _is_browser(name, exe):
            continue
        try:
            for fp in _open_files(pid):
                if fp.lower() in cred_set:
                    report.add(Finding(
                        kind="cred_access", pid=pid, process_name=name,
                        detail="Non-browser process has credential DB open",
                        cred_path=fp, severity="critical",
                    ))
        except Exception:
            report.errors += 1

    # 3. Recently modified credential databases
    report.findings.extend(_check_recent_modifications(cred_paths))

    # 4. DPAPI master key access (Windows)
    if check_dpapi and IS_WIN:
        try:
            report.findings.extend(_check_dpapi_access())
        except Exception as exc:
            log.debug("DPAPI check failed: %s", exc)
            report.errors += 1
    return report


# .  CLI . . . . . -

def main() -> None:
    import argparse, sys  # noqa: E401
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="Browser credential store access detector")
    parser.add_argument("--no-dpapi", action="store_true", help="Skip DPAPI checks")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    if args.verbose:
        logging.getLogger(__name__).setLevel(logging.DEBUG)

    report = scan(check_dpapi=not args.no_dpapi)
    print(f"\nCredential store scan complete")
    print(f"  cred DBs found    : {report.cred_dbs_found}")
    print(f"  processes checked : {report.processes_checked}")
    print(f"  findings          : {len(report.findings)}")
    print(f"  errors            : {report.errors}")
    if report.clean:
        print("  status            : CLEAN\n")
        sys.exit(0)
    print()
    for f in report.findings:
        tag = f"[{f.severity.upper()}]"
        print(f"  {tag:10} {f.kind}")
        print(f"    process : {f.process_name} (pid {f.pid})")
        print(f"    target  : {f.cred_path}")
        print(f"    detail  : {f.detail}\n")
    sys.exit(1)


if __name__ == "__main__":
    main()
