"""
persistence.py - Sentinel persistence mechanism detection.

Each finding dict has keys: type, path, value, severity (low/medium/high/critical), note.
"""

import os
import platform
import subprocess
from typing import Any

SYSTEM = platform.system()

if SYSTEM == "Windows":
    import winreg  # noqa: F401 - guarded import; absent on Linux

Finding = dict[str, str]

WIN_STD = ("C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)")
WIN_SUSPECT = ("temp", "tmp", "appdata", "programdata", "users")


def _reg_vals(hive: int, subkey: str) -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    try:
        k = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
        i = 0
        while True:
            try:
                n, d, _ = winreg.EnumValue(k, i); out.append((n, d)); i += 1
            except OSError:
                break
        winreg.CloseKey(k)
    except OSError:
        pass
    return out


def _run(cmd: list[str], timeout: int = 15) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def _f(t: str, p: str, v: str, sev: str, note: str) -> Finding:
    return {"type": t, "path": p, "value": str(v), "severity": sev, "note": note}


def _check_run_keys() -> list[Finding]:
    """Run/RunOnce keys under HKLM and HKCU."""
    out = []
    for hive, hname in ((winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")):
        for kp in ("Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                   "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"):
            for name, data in _reg_vals(hive, kp):
                sl = str(data).lower()
                sev = "critical" if any(d in sl for d in WIN_SUSPECT) else "high"
                note = ("Run key points to a temp or user-writable path" if sev == "critical"
                        else "Run key entry; verify this program is expected")
                out.append(_f("registry_run", f"{hname}\\{kp}", name, sev, note))
    return out


def _check_winlogon() -> list[Finding]:
    """Winlogon Shell/Userinit changes are a classic hijack method."""
    out = []
    kp = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
    defaults = {"shell": "explorer.exe",
                "userinit": "C:\\Windows\\system32\\userinit.exe,"}
    for n, d in _reg_vals(winreg.HKEY_LOCAL_MACHINE, kp):
        nl = n.lower()
        if nl in defaults and str(d).strip() != defaults[nl]:
            out.append(_f("winlogon_hijack", f"HKLM\\{kp}", f"{n}={d}",
                          "critical", f"Winlogon {n} differs from default '{defaults[nl]}'"))
    return out


def _check_ifeo() -> list[Finding]:
    """IFEO Debugger values silently redirect any process to a different binary."""
    out = []
    kp = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, kp, 0, winreg.KEY_READ)
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(root, i); i += 1
                for vn, vd in _reg_vals(winreg.HKEY_LOCAL_MACHINE, f"{kp}\\{sub}"):
                    if vn.lower() == "debugger":
                        out.append(_f("ifeo_hijack", f"HKLM\\{kp}\\{sub}",
                                      str(vd), "critical", "Debugger value intercepts process launch"))
            except OSError:
                break
        winreg.CloseKey(root)
    except OSError:
        pass
    return out


def _check_appinit() -> list[Finding]:
    """AppInit_DLLs inject into every process that loads user32.dll."""
    out = []
    kp = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
    for n, d in _reg_vals(winreg.HKEY_LOCAL_MACHINE, kp):
        nl = n.lower()
        if nl == "appinit_dlls" and str(d).strip():
            out.append(_f("appinit_dlls", f"HKLM\\{kp}", str(d),
                          "critical", "DLL injected into every user32-linked process"))
        elif nl == "loadappinit_dlls" and str(d) not in ("0", ""):
            out.append(_f("appinit_dlls", f"HKLM\\{kp}", f"LoadAppInit_DLLs={d}",
                          "high", "LoadAppInit_DLLs enabled; check AppInit_DLLs value"))
    return out


def _check_wmi_subscriptions() -> list[Finding]:
    """WMI subscriptions in root/subscription persist across reboots with no file footprint."""
    out = []
    for cls in ("__EventFilter", "CommandLineEventConsumer", "__FilterToConsumerBinding"):
        raw = _run(["powershell", "-NonInteractive", "-Command",
                    f"Get-CimInstance -Namespace root/subscription -ClassName {cls}"
                    " | Select-Object Name,CommandLineTemplate,Query"
                    " | ConvertTo-Csv -NoTypeInformation"])
        for line in raw.splitlines()[1:]:
            line = line.strip().strip('"')
            if line:
                out.append(_f("wmi_subscription", f"root/subscription:{cls}", line,
                               "critical", "WMI event subscription runs code on system events"))
    return out


def _check_scheduled_tasks() -> list[Finding]:
    """Tasks with a non-Microsoft author or an action in a suspect directory."""
    out = []
    raw = _run(["powershell", "-NonInteractive", "-Command",
                "Get-ScheduledTask | Select-Object TaskName,TaskPath,"
                "@{n='Author';e={$_.Principal.UserId}},"
                "@{n='Action';e={($_.Actions | Select-Object -First 1).Execute}}"
                " | ConvertTo-Csv -NoTypeInformation"])
    for line in raw.splitlines()[1:]:
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) < 4:
            continue
        name, path, author, action = parts[:4]
        al = action.lower()
        if any(d in al for d in WIN_SUSPECT):
            out.append(_f("scheduled_task", path + name, action,
                          "critical", "Task action targets a temp or user-writable path"))
        elif "microsoft" not in (author or "").lower():
            out.append(_f("scheduled_task", path + name, f"Author={author} Action={action}",
                          "medium", "Non-Microsoft scheduled task; verify it is expected"))
    return out


def _check_startup_folders() -> list[Finding]:
    """Anything in a startup folder runs at logon."""
    out = []
    for folder in (os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
                   r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"):
        if not os.path.isdir(folder):
            continue
        for fname in os.listdir(folder):
            if not fname.startswith("."):
                out.append(_f("startup_folder", folder, fname,
                               "high", "File in startup folder executes at logon"))
    return out


def _check_services() -> list[Finding]:
    """Services with an ImagePath outside standard Windows install directories."""
    out = []
    kp = "SYSTEM\\CurrentControlSet\\Services"
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, kp, 0, winreg.KEY_READ)
        i = 0
        while True:
            try:
                svc = winreg.EnumKey(root, i); i += 1
                for vn, vd in _reg_vals(winreg.HKEY_LOCAL_MACHINE, f"{kp}\\{svc}"):
                    if vn.lower() == "imagepath":
                        vl = str(vd).lower().strip('"').lstrip("\\??\\")
                        if vl and not any(vl.startswith(p.lower()) for p in WIN_STD):
                            sev = "critical" if any(d in vl for d in WIN_SUSPECT) else "high"
                            out.append(_f("service_nonstandard_path", f"HKLM\\{kp}\\{svc}",
                                          str(vd), sev, "Service binary outside standard install paths"))
            except OSError:
                break
        winreg.CloseKey(root)
    except OSError:
        pass
    return out


def _check_crontabs() -> list[Finding]:
    """User and system crontab entries."""
    out = []
    for line in _run(["crontab", "-l"]).splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(_f("crontab", "crontab -l", line, "medium", "User crontab entry"))
    for p in ("/etc/crontab", "/etc/cron.d"):
        files = [p] if os.path.isfile(p) else (
            [os.path.join(p, f) for f in os.listdir(p)] if os.path.isdir(p) else [])
        for fp in files:
            try:
                for line in open(fp):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        out.append(_f("crontab", fp, line, "medium", "System crontab entry"))
            except OSError:
                pass
    return out


def _check_systemd_units() -> list[Finding]:
    """Systemd units outside /usr/lib/systemd or /lib/systemd."""
    out = []
    standard = ("/usr/lib/systemd", "/lib/systemd")
    for base in ("/etc/systemd", os.path.expanduser("~/.config/systemd")):
        if not os.path.isdir(base):
            continue
        for root_dir, _, files in os.walk(base):
            for fname in files:
                if fname.endswith((".service", ".timer", ".socket")):
                    fp = os.path.join(root_dir, fname)
                    if not any(fp.startswith(s) for s in standard):
                        out.append(_f("systemd_unit", fp, fname,
                                      "high", "Systemd unit in non-standard path"))
    return out


def _check_rc_injection() -> list[Finding]:
    """Shell RC files containing network tools or decode commands."""
    out = []
    rc_files = [os.path.expanduser(f) for f in
                ("~/.bashrc", "~/.bash_profile", "~/.profile", "~/.zshrc", "~/.zprofile")]
    triggers = ("curl ", "wget ", "base64", "/tmp/", "nc ", "ncat ", "bash -i")
    for fp in rc_files:
        if not os.path.isfile(fp):
            continue
        try:
            for i, line in enumerate(open(fp), 1):
                s = line.strip()
                if s and not s.startswith("#") and any(t in s for t in triggers):
                    out.append(_f("rc_injection", fp, f"line {i}: {s[:120]}",
                                  "critical", "Shell RC contains a network or decode command"))
        except OSError:
            pass
    return out


def _check_initd() -> list[Finding]:
    """Non-symlinked scripts in /etc/init.d may have been placed there manually."""
    out = []
    if not os.path.isdir("/etc/init.d"):
        return out
    for fname in os.listdir("/etc/init.d"):
        fp = os.path.join("/etc/init.d", fname)
        if os.path.isfile(fp) and not os.path.islink(fp):
            out.append(_f("initd_script", fp, fname, "medium",
                          "Init.d script is not a symlink"))
    return out


def scan() -> list[Finding]:
    """Run all checks for the current OS and return findings."""
    findings: list[Finding] = []
    checks = ([_check_run_keys, _check_winlogon, _check_ifeo, _check_appinit,
               _check_wmi_subscriptions, _check_scheduled_tasks,
               _check_startup_folders, _check_services]
              if SYSTEM == "Windows" else
              [_check_crontabs, _check_systemd_units, _check_rc_injection, _check_initd])
    for check in checks:
        try:
            findings.extend(check())
        except Exception:
            pass
    return findings


if __name__ == "__main__":
    results = scan()
    if not results:
        print("No persistence findings.")
    for f in results:
        print(f"[{f['severity'].upper():8}] {f['type']} | {f['path']} | {f['value'][:80]}")
        print(f"           {f['note']}")
