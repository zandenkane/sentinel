"""
Process tree behavioral analysis .  LOLBin abuse, signed-tool misuse,
unauthorized RMM detection, and parent-child relationship anomalies.

Builds a snapshot of the full process tree via psutil and applies
rule-based detection for suspicious parent-child chains, encoded
PowerShell, download cradles, LOLBAS patterns, unauthorized RMM tools,
and rapid chain-spawn timing anomalies.

Windows primary. Returns list[Finding] from sentinel.finding.
"""
from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Optional

import psutil

from sentinel.finding import Finding

log = logging.getLogger(__name__)
MODULE = "proctree"

# .  parent-child rule tables (lowercase, no .exe) . 
OFFICE_PARENTS = {
    "winword", "excel", "powerpnt", "outlook", "msaccess",
    "mspub", "onenote", "visio",
}
SHELL_CHILDREN = {
    "cmd", "powershell", "pwsh", "wscript", "cscript",
    "mshta", "certutil", "regsvr32", "rundll32", "msiexec",
    "bitsadmin", "bash", "curl", "wget",
}
SVCHOST_OK = {
    "wuauclt", "taskhostw", "sihost", "ctfmon", "runtimebroker",
    "dllhost", "conhost", "audiodg", "searchprotocolhost",
    "searchfilterhost", "smartscreen", "backgroundtaskhost",
    "mousocoreworker", "usocoreworker", "systemsettings",
    "settingsynchost", "wlanext", "spoolsv", "dashost", "wmiprvse",
}
SERVICES_OK = {
    "svchost", "spoolsv", "msdtc", "vds", "searchindexer", "lsass",
    "dllhost", "wininit", "taskhost", "msiexec", "trustedinstaller",
    "tiworker", "securityhealthservice", "msmpeng", "nissrv",
    "smartscreen", "sgrmbroker", "fontdrvhost", "officesvcmgr",
    "wudfhost", "vmms", "vmcompute", "wslservice",
    "officeclicktorun", "gamingservices", "gamingservicesnet",
    "gameinputsvc", "mpdefendercoreservice", "wmiregistrationservice",
}
WMI_BAD = {"cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "certutil", "rundll32"}
EXPLORER_WATCH = {"powershell", "pwsh", "cmd", "mshta", "wscript", "cscript"}
SVCHOST_BAD = {"cmd", "powershell", "pwsh", "mshta", "wscript", "cscript",
               "certutil", "rundll32", "regsvr32"}

# .  RMM tools . 
RMM_TOOLS: dict[str, str] = {
    "anydesk": "AnyDesk", "teamviewer": "TeamViewer",
    "teamviewer_service": "TeamViewer",
    "screenconnect": "ScreenConnect", "screenconnect.clientservice": "ScreenConnect",
    "screenconnect.windowsclient": "ScreenConnect",
    "rustdesk": "RustDesk", "splashtop": "Splashtop",
    "srmanager": "Splashtop", "sragent": "Splashtop",
    "atera_agent": "Atera", "ateraagent": "Atera",
    "connectwise": "ConnectWise", "cwcontrol": "ConnectWise",
}
APPROVED_RMM: set[str] = set()
_RMM_VENDOR_FRAG: dict[str, str] = {
    "AnyDesk": "/anydesk/", "TeamViewer": "/teamviewer/",
    "ScreenConnect": "/screenconnect/", "ConnectWise": "/connectwise/",
    "RustDesk": "/rustdesk/", "Splashtop": "/splashtop/", "Atera": "/atera/",
}
_SUSPECT_FRAGS = ("/temp/", "/tmp/", "/appdata/local/temp", "/appdata/roaming/",
                  "/public/", "/downloads/", "/desktop/", "/users/default/")

# .  cmdline regexes (compiled once) . 
_PS_ENC = re.compile(
    r"-e(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:nd?)?)?)?)?)?)?)?)?)?)?)?)?(?:\s|$)",
    re.IGNORECASE)
_B64_BLOB = re.compile(r"[A-Za-z0-9+/=]{40,}")
_PS_STEALTH: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-w(?:indowstyle)?\s+h(?:idden)?", re.I), "hidden window"),
    (re.compile(r"-nop(?:rofile)?", re.I), "no profile"),
    (re.compile(r"-(?:ep|executionpolicy)\s+bypass", re.I), "exec policy bypass"),
    (re.compile(r"-noni(?:nteractive)?", re.I), "non-interactive"),
]
_CRADLES: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"iex\s*\(", re.I), "IEX cradle", "T1059.001"),
    (re.compile(r"invoke-expression", re.I), "Invoke-Expression", "T1059.001"),
    (re.compile(r"invoke-webrequest", re.I), "Invoke-WebRequest", "T1105"),
    (re.compile(r"downloadstring", re.I), "DownloadString", "T1105"),
    (re.compile(r"downloadfile", re.I), "DownloadFile", "T1105"),
    (re.compile(r"frombase64string", re.I), "FromBase64String", "T1027"),
    (re.compile(r"certutil\s.*-urlcache", re.I), "certutil download", "T1105"),
    (re.compile(r"bitsadmin\s.*/transfer", re.I), "BITS transfer", "T1105"),
    (re.compile(r"start-bitstransfer", re.I), "Start-BitsTransfer", "T1105"),
]
_LOLBAS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"mshta\s+(?:vbscript|javascript):", re.I), "mshta script exec", "T1218.005"),
    (re.compile(r"mshta\s+https?://", re.I), "mshta remote HTA", "T1218.005"),
    (re.compile(r"regsvr32\s.*/s\s.*/n\s.*/u\s.*scrobj\.dll", re.I),
     "regsvr32 Squiblydoo", "T1218.010"),
    (re.compile(r"regsvr32\s.*/i:https?://", re.I), "regsvr32 remote scriptlet", "T1218.010"),
    (re.compile(r"rundll32\s.*javascript:", re.I), "rundll32 JS exec", "T1218.011"),
    (re.compile(r"forfiles\s.*/c\s", re.I), "forfiles cmd exec", "T1202"),
]

CHAIN_WINDOW_SEC = 3.0
CHAIN_MIN_LEN = 3
ProcessInfo = dict[str, object]


def _n(name: Optional[str]) -> str:
    """Normalize process name: lowercase, strip .exe/.bin."""
    return (name or "").lower().replace(".exe", "").replace(".bin", "").strip()


def _cmd(info: ProcessInfo) -> str:
    raw = info.get("cmdline")
    if not raw:
        return ""
    return " ".join(str(a) for a in raw) if isinstance(raw, list) else str(raw)


def _exe(info: ProcessInfo) -> str:
    return str(info.get("exe") or "")


def _lbl(info: ProcessInfo) -> str:
    return f"{info.get('name', '?')}(pid {info.get('pid', '?')})"


def _f(title: str, sev: str, detail: str, evidence: str,
       mitre: str = "", path: str = "", pid: int = 0) -> Finding:
    return Finding(module=MODULE, title=title, severity=sev,
                   detail=detail, evidence=evidence, mitre_id=mitre, path=path, pid=pid)


# .  snapshot . 
def _snapshot() -> tuple[dict[int, ProcessInfo], dict[int, list[int]]]:
    attrs = ["pid", "ppid", "name", "exe", "cmdline", "create_time"]
    by_pid: dict[int, ProcessInfo] = {}
    children: dict[int, list[int]] = defaultdict(list)
    for proc in psutil.process_iter(attrs):
        try:
            info = proc.info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        pid = info.get("pid")
        if pid is None:
            continue
        by_pid[pid] = info
        ppid = info.get("ppid")
        if ppid and ppid != 0:
            children[ppid].append(pid)
    return by_pid, children


def _time_ok(parent: ProcessInfo, child: ProcessInfo) -> bool:
    """PID-reuse guard: parent create_time must precede child."""
    pt, ct = parent.get("create_time"), child.get("create_time")
    if pt is None or ct is None:
        return True
    try:
        return float(pt) <= float(ct)
    except (TypeError, ValueError):
        return True


# .  1. parent-child rules . 
def _check_tree(bp: dict[int, ProcessInfo], ch: dict[int, list[int]]) -> list[Finding]:
    out: list[Finding] = []
    for ppid, kids in ch.items():
        par = bp.get(ppid)
        if par is None:
            continue
        pn = _n(str(par.get("name", "")))
        for cpid in kids:
            ci = bp.get(cpid)
            if ci is None or not _time_ok(par, ci):
                continue
            cn = _n(str(ci.get("name", "")))
            ev = f"{_lbl(par)} -> {_lbl(ci)}"
            ce = _exe(ci)

            if pn in OFFICE_PARENTS and cn in SHELL_CHILDREN:
                out.append(_f(f"Office app spawned {cn}", "high",
                              f"{pn} spawned {cn} (macro/exploit chain indicator)", ev,
                              "T1204.002", ce, cpid))
            if pn == "wmiprvse" and cn in WMI_BAD:
                out.append(_f(f"WMI provider spawned {cn}", "high",
                              f"wmiprvse spawned {cn} (WMI lateral movement)", ev,
                              "T1047", ce, cpid))
            if pn == "svchost" and cn not in SVCHOST_OK and cn in SVCHOST_BAD:
                out.append(_f(f"svchost spawned {cn}", "high",
                              f"svchost spawned unexpected {cn}", ev,
                              "T1059", ce, cpid))
            if pn == "services" and cn not in SERVICES_OK:
                out.append(_f(f"services.exe spawned unexpected child {cn}", "medium",
                              f"services.exe spawned {cn}, not a recognized service binary",
                              ev, "T1543.003", ce, cpid))
            if pn == "explorer" and cn in EXPLORER_WATCH:
                cl = _cmd(ci)
                if _PS_ENC.search(cl):
                    out.append(_f("explorer spawned encoded PowerShell", "high",
                                  "explorer spawned shell with encoded command", ev +
                                  f" | cmdline: {cl[:200]}", "T1059.001", ce, cpid))
    return out


# .  2. command-line analysis . 
def _check_cmdline(bp: dict[int, ProcessInfo]) -> list[Finding]:
    out: list[Finding] = []
    for pid, info in bp.items():
        cl = _cmd(info)
        if not cl:
            continue
        nm = _n(str(info.get("name", "")))
        ex = _exe(info)

        # encoded PowerShell
        if nm in {"powershell", "pwsh"} and _PS_ENC.search(cl):
            b64 = _B64_BLOB.search(cl)
            snip = (b64.group(0)[:80] + "...") if b64 else ""
            flags = [d for p, d in _PS_STEALTH if p.search(cl)]
            sev = "critical" if flags else "high"
            det = "PowerShell with encoded command"
            if flags:
                det += f"; stealth: {', '.join(flags)}"
            ev = f"cmdline: {cl[:300]}"
            if snip:
                ev += f" | b64: {snip}"
            out.append(_f("Encoded PowerShell execution", sev, det, ev,
                          "T1059.001", ex, pid))

        # download cradles (one per process)
        for pat, desc, mitre in _CRADLES:
            if pat.search(cl):
                out.append(_f(f"Download cradle: {desc}", "high",
                              f"{desc} in cmdline of {nm}", f"cmdline: {cl[:300]}",
                              mitre, ex, pid))
                break

        # LOLBAS patterns
        for pat, desc, mitre in _LOLBAS:
            if pat.search(cl):
                out.append(_f(f"LOLBAS abuse: {desc}", "high",
                              f"{desc} detected in {nm}", f"cmdline: {cl[:300]}",
                              mitre, ex, pid))
    return out


# .  3. unauthorized RMM . 
def _check_rmm(bp: dict[int, ProcessInfo]) -> list[Finding]:
    out: list[Finding] = []
    for pid, info in bp.items():
        nm = _n(str(info.get("name", "")))
        if nm not in RMM_TOOLS:
            continue
        vendor = RMM_TOOLS[nm]
        if vendor in APPROVED_RMM:
            continue
        ex = _exe(info)
        norm = ex.lower().replace("\\", "/") if ex else ""
        suspect = any(f in norm for f in _SUSPECT_FRAGS) if norm else False
        vendor_path = (_RMM_VENDOR_FRAG.get(vendor, "") in norm) if norm else False
        if suspect:
            out.append(_f(f"RMM from suspect path: {vendor}", "high",
                          f"{vendor} ({nm}) from non-standard path", f"exe: {ex}",
                          "T1219", ex, pid))
        elif not vendor_path:
            out.append(_f(f"Unauthorized RMM: {vendor}", "medium",
                          f"{vendor} ({nm}) not in approved RMM list",
                          f"exe: {ex or '(unknown)'}", "T1219", ex, pid))
        else:
            out.append(_f(f"Unapproved RMM: {vendor}", "low",
                          f"{vendor} ({nm}) in vendor path but not approved",
                          f"exe: {ex}", "T1219", ex, pid))
    return out


# .  4. chain timing anomalies . 
# Chains only flag when they contain at least one suspicious process name
_CHAIN_SUSPECT = SHELL_CHILDREN | {"mshta", "certutil", "regsvr32", "rundll32", "bitsadmin"}

def _check_chains(bp: dict[int, ProcessInfo], ch: dict[int, list[int]]) -> list[Finding]:
    out: list[Finding] = []
    seen_chains: set[frozenset[int]] = set()

    def walk(pid: int, local_seen: set[int]) -> list[int]:
        chain = [pid]
        local_seen.add(pid)
        best: list[int] = []
        for kid in ch.get(pid, []):
            if kid not in local_seen:
                sub = walk(kid, local_seen)
                if len(sub) > len(best):
                    best = sub
        return chain + best

    roots = {pid for pid in ch if pid in bp}
    for pid in roots:
        chain = walk(pid, set())
        if len(chain) < CHAIN_MIN_LEN:
            continue
        # Require at least one suspicious binary in the chain
        names = {_n(str((bp.get(p) or {}).get("name", ""))) for p in chain}
        if not names & _CHAIN_SUSPECT:
            continue
        key = frozenset(chain)
        if key in seen_chains:
            continue
        seen_chains.add(key)
        times: list[float] = []
        for cpid in chain:
            ct = (bp.get(cpid) or {}).get("create_time")
            if ct is not None:
                try:
                    times.append(float(ct))
                except (TypeError, ValueError):
                    pass
        if len(times) < CHAIN_MIN_LEN:
            continue
        span = max(times) - min(times)
        if span <= CHAIN_WINDOW_SEC:
            labels = [_lbl(bp[p]) for p in chain if p in bp]
            out.append(_f("Rapid process chain detected", "high",
                          f"{len(chain)} processes in {span:.1f}s (automated exploitation)",
                          " -> ".join(labels), "T1106", pid=chain[0]))
    return out


# .  public API . 
def scan(
    approved_rmm: Optional[set[str]] = None,
    chain_window: float = CHAIN_WINDOW_SEC,
    chain_min: int = CHAIN_MIN_LEN,
) -> list[Finding]:
    """Run all process tree behavioral checks. Returns list[Finding]."""
    global CHAIN_WINDOW_SEC, CHAIN_MIN_LEN
    if approved_rmm is not None:
        APPROVED_RMM.clear()
        APPROVED_RMM.update(approved_rmm)
    CHAIN_WINDOW_SEC = chain_window
    CHAIN_MIN_LEN = chain_min

    try:
        bp, ch = _snapshot()
    except Exception as exc:
        log.error("failed to snapshot process tree: %s", exc)
        return [_f("Process tree snapshot failed", "info",
                    f"Could not enumerate processes: {exc}", type(exc).__name__)]

    findings: list[Finding] = []
    findings.extend(_check_tree(bp, ch))
    findings.extend(_check_cmdline(bp))
    findings.extend(_check_rmm(bp))
    findings.extend(_check_chains(bp, ch))
    log.info("proctree: %d processes, %d findings", len(bp), len(findings))
    return findings