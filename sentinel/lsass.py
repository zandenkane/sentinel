"""
LSASS access detection. Identifies processes touching lsass.exe memory,
dump file artifacts, PPL status, and suspicious child processes.
Windows primary (handle enumeration), Linux secondary (ptrace / /proc/mem).
"""
from __future__ import annotations

import logging
import os
import platform
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import psutil

log = logging.getLogger(__name__)
IS_WIN = platform.system() == "Windows"

_SYSTEM_ACCESSORS: set[str] = {
    "csrss.exe", "services.exe", "svchost.exe", "wininit.exe", "smss.exe",
    "mrt.exe", "taskmgr.exe", "lsass.exe", "winlogon.exe", "system",
    "registry", "msmpeng.exe", "securityhealthservice.exe", "mpcmdrun.exe",
}
_DUMP_TOOLS: set[str] = {
    "mimikatz", "procdump", "procdump64", "nanodump", "ppldump",
    "handlekatz", "lsassy", "pypykatz", "dumpert", "physmem2profit",
}
_DUMP_PATTERNS = ["lsass.dmp", "lsass.zip", "lsass_dump", "procdump_lsass", "lsass.pmd"]
_SUSPECT_FRAGS = ["/temp/", "/tmp/", "/appdata/local/temp", "/appdata/roaming/",
                  "/public/", "/downloads/", "/desktop/", "/users/default/"]
_LINUX_SENSITIVE: set[str] = {"sshd", "gpg-agent", "gnome-keyring-daemon",
                              "ssh-agent", "sudo", "passwd", "login"}


@dataclass
class Finding:
    accessor_pid: int
    accessor_name: str
    accessor_exe: Optional[str]
    access_type: str   # handle | dump_file | child_process | ppl_status | ptrace
    reason: str


@dataclass
class LsassReport:
    findings: list[Finding] = field(default_factory=list)
    lsass_pid: Optional[int] = None
    ppl_enabled: Optional[bool] = None
    errors: int = 0
    def add(self, f: Finding) -> None: self.findings.append(f)
    @property
    def clean(self) -> bool: return len(self.findings) == 0


def _find_lsass() -> Optional[psutil.Process]:
    for p in psutil.process_iter(["pid", "name"]):
        if (p.info["name"] or "").lower() == "lsass.exe":
            return p
    return None


def _suspect_path(exe: str) -> bool:
    low = exe.lower().replace("\\", "/")
    return any(f in low for f in _SUSPECT_FRAGS)


def _check_handles(lsass_pid: int) -> list[Finding]:
    """Enumerate running processes; flag dump tools or suspect-path binaries."""
    out: list[Finding] = []
    ps = (f'Get-Process | Where-Object {{ $_.Id -ne {lsass_pid} }} | '
          f'ForEach-Object {{ try {{ Write-Output "$($_.Id)|$($_.ProcessName)|$($_.Path)" }}'
          f' catch {{}} }}')
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, text=True, timeout=30)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        log.warning("handle enumeration: %s", e); return out
    for line in r.stdout.strip().splitlines():
        parts = line.strip().split("|", 2)
        if len(parts) < 2: continue
        try: pid = int(parts[0])
        except ValueError: continue
        name, exe = parts[1], (parts[2] if len(parts) > 2 else None)
        stem = name.lower().replace(".exe", "")
        if stem in _DUMP_TOOLS:
            out.append(Finding(pid, name, exe, "handle",
                f"credential-dumping tool '{name}' running alongside lsass"))
        elif name.lower() not in _SYSTEM_ACCESSORS and exe and _suspect_path(exe):
            out.append(Finding(pid, name, exe, "handle",
                "non-system process from suspect path has handles open"))
    return out


def _check_ppl(lsass_pid: int) -> tuple[Optional[bool], list[Finding]]:
    """Query RunAsPPL registry value."""
    ppl: Optional[bool] = None
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Control\Lsa") as k:
            val, _ = winreg.QueryValueEx(k, "RunAsPPL"); ppl = bool(val)
    except FileNotFoundError: ppl = False
    except OSError as e: log.debug("RunAsPPL read failed: %s", e)
    findings: list[Finding] = []
    if ppl is False:
        findings.append(Finding(lsass_pid, "lsass.exe", None, "ppl_status",
            "LSASS not running as PPL; dump tools can read its memory. "
            "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL=1"))
    return ppl, findings


def _check_dump_files() -> list[Finding]:
    """Scan temp/user dirs for LSASS dump artifacts."""
    out: list[Finding] = []
    dirs = {os.environ.get("TEMP", ""), os.environ.get("TMP", ""),
            os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "Temp"),
            os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"),
            os.path.join(os.environ.get("USERPROFILE", ""), "Downloads")}
    for d in dirs:
        if not d: continue
        try: entries = os.listdir(d)
        except (PermissionError, FileNotFoundError, OSError): continue
        for e in entries:
            el = e.lower()
            fp = os.path.join(d, e)
            if any(p in el for p in _DUMP_PATTERNS):
                out.append(Finding(0, "filesystem", fp, "dump_file",
                    f"LSASS dump artifact: {fp}"))
            elif el.endswith(".dmp") and "temp" in d.lower():
                try: sz = os.path.getsize(fp)
                except OSError: sz = 0
                if sz > 20 * 1024 * 1024:
                    out.append(Finding(0, "filesystem", fp, "dump_file",
                        f"large .dmp ({sz//(1024*1024)} MB) in temp dir: {fp}"))
    return out


def _check_children(lsass_pid: int) -> list[Finding]:
    """LSASS should not spawn user-mode children."""
    out: list[Finding] = []
    try: children = psutil.Process(lsass_pid).children(recursive=False)
    except (psutil.NoSuchProcess, psutil.AccessDenied): return out
    for ch in children:
        try: cn, ce = ch.name() or f"<pid:{ch.pid}>", ch.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied): continue
        out.append(Finding(ch.pid, cn, ce, "child_process",
            f"lsass (pid {lsass_pid}) spawned '{cn}'; "
            f"may indicate process injection or hollowing"))
    return out


def _check_linux_ptrace() -> list[Finding]:
    """Check ptrace scope, active tracers, and /proc/mem readers."""
    out: list[Finding] = []
    scope = Path("/proc/sys/kernel/yama/ptrace_scope")
    if scope.exists():
        try:
            if scope.read_text().strip() == "0":
                out.append(Finding(0, "kernel", None, "ptrace",
                    "ptrace_scope=0; any same-uid process can attach. "
                    "Set kernel.yama.ptrace_scope=1"))
        except OSError: pass
    sens: dict[int, str] = {}
    for p in psutil.process_iter(["pid", "name"]):
        pn = (p.info["name"] or "").lower()
        if pn in _LINUX_SENSITIVE: sens[p.info["pid"]] = pn
    if not sens: return out
    for spid, sname in sens.items():
        try:
            for line in Path(f"/proc/{spid}/status").read_text().splitlines():
                if not line.startswith("TracerPid:"): continue
                tpid = int(line.split(":")[1].strip())
                if tpid:
                    tn, te = "<unknown>", None
                    try:
                        tp = psutil.Process(tpid); tn, te = tp.name() or tn, tp.exe()
                    except (psutil.NoSuchProcess, psutil.AccessDenied): pass
                    out.append(Finding(tpid, tn, te, "ptrace",
                        f"'{tn}' (pid {tpid}) ptracing '{sname}' (pid {spid})"))
                break
        except (PermissionError, FileNotFoundError, OSError): continue
    for p in psutil.process_iter(["pid", "name"]):
        try: fds = p.open_files()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError): continue
        for fd in fds:
            for spid, sname in sens.items():
                if f"/proc/{spid}/mem" in fd.path:
                    out.append(Finding(p.info["pid"], p.info["name"] or "<unknown>",
                        None, "ptrace", f"has /proc/{spid}/mem open ('{sname}'); "
                        f"direct memory read on credential process"))
    return out


def scan_lsass() -> LsassReport:
    """Run all LSASS / credential-process access checks."""
    report = LsassReport()
    if IS_WIN:
        lsass = _find_lsass()
        if not lsass:
            log.error("could not locate lsass.exe"); report.errors += 1; return report
        report.lsass_pid = lsass.pid
        log.info("lsass.exe at pid %d", lsass.pid)
        for label, fn in [("handles", lambda: _check_handles(lsass.pid)),
                          ("dump_files", _check_dump_files),
                          ("children", lambda: _check_children(lsass.pid))]:
            try:
                for f in fn(): report.add(f)
            except Exception as e: log.warning("%s: %s", label, e); report.errors += 1
        try:
            ppl, pf = _check_ppl(lsass.pid); report.ppl_enabled = ppl
            for f in pf: report.add(f)
        except Exception as e: log.warning("ppl: %s", e); report.errors += 1
    else:
        try:
            for f in _check_linux_ptrace(): report.add(f)
        except Exception as e: log.warning("ptrace: %s", e); report.errors += 1
    return report
