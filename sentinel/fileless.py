"""
Fileless malware and in-memory threat detection for Windows.

Detects:
  1. .NET assembly loading from memory via ETW (Microsoft-Windows-DotNETRuntime)
  2. Suspicious PowerShell script blocks (Event ID 4104)
  3. Process injection via unbacked executable regions + CreateRemoteThread
  4. CLR loading in processes that normally never use .NET

Windows-only. On non-Windows platforms, run() returns an empty list.
"""

from __future__ import annotations

import ctypes
import logging
import platform
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

import psutil

from sentinel.finding import Finding

log = logging.getLogger(__name__)

IS_WIN = platform.system() == "Windows"

# . . . . . . . . . . . . . . . . . . . -
# MITRE ATT&CK technique references
# . . . . . . . . . . . . . . . . . . . -
MITRE_REFLECTIVE_LOAD = "T1620"        # Reflective Code Loading
MITRE_PROCESS_INJECTION = "T1055"      # Process Injection
MITRE_CREATE_REMOTE_THREAD = "T1055.003"
MITRE_POWERSHELL = "T1059.001"         # Command and Scripting: PowerShell
MITRE_DOTNET_EXEC = "T1218"            # System Binary Proxy Execution (CLR abuse)

MODULE_NAME = "fileless"

# . . . . . . . . . . . . . . . . . . . -
# PowerShell 4104 suspicious indicators
# . . . . . . . . . . . . . . . . . . . -
PS_INDICATORS: list[str] = [
    "IEX",
    "Invoke-Expression",
    "[System.Reflection.Assembly]::Load",
    "[Runtime.InteropServices.Marshal]",
    "Add-Type",
    "Net.WebClient",
    "DownloadString",
    "DownloadData",
    "FromBase64String",
    "EncodedCommand",
    "Invoke-Mimikatz",
    "Invoke-Shellcode",
]

# Processes that should never load the CLR under normal circumstances.
# NOTE: On Windows 11 the Store versions of Notepad and Calculator are
# WinUI / UWP apps and CAN legitimately load .NET. This list is kept as
# a heuristic per the classic detection playbook; findings are medium
# severity to account for possible false positives.
NON_DOTNET_PROCESSES: set[str] = {
    "notepad.exe", "calc.exe", "mspaint.exe", "wordpad.exe",
    "write.exe", "charmap.exe", "osk.exe", "magnify.exe",
    "snippingtool.exe", "mstsc.exe", "cmd.exe",
}

CLR_DLLS: set[str] = {"clr.dll", "clrjit.dll", "coreclr.dll", "mscoreei.dll"}

# Temp / user directory fragments that flag suspicious assembly loads
SUSPECT_PATH_FRAGS: list[str] = [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp",
    "\\appdata\\roaming\\", "\\public\\", "\\downloads\\",
    "\\users\\default\\",
]


# ===================================================================
# 1. ETW consumer for .NET assembly loading
# ===================================================================
# The real-time ETW trace only captures loads that happen DURING the
# collection window. Already-loaded assemblies require the Rundown
# provider which adds significant complexity and is omitted here.

if IS_WIN:
    import ctypes.wintypes

    # Provider GUID: Microsoft-Windows-DotNETRuntime
    # {E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}
    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", ctypes.c_ulong),
            ("Data2", ctypes.c_ushort),
            ("Data3", ctypes.c_ushort),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    WNODE_FLAG_TRACED_GUID: int = 0x00020000
    EVENT_TRACE_REAL_TIME_MODE: int = 0x00000100
    ERROR_ALREADY_EXISTS: int = 183
    ERROR_ACCESS_DENIED: int = 5

    SESSION_NAME = "SentinelDotNetTrace"
    SESSION_NAME_W = SESSION_NAME + "\0"
    EVENT_TRACE_CONTROL_STOP = 1

    class WNODE_HEADER(ctypes.Structure):
        _fields_ = [
            ("BufferSize", ctypes.c_ulong),
            ("ProviderId", ctypes.c_ulong),
            ("HistoricalContext", ctypes.c_ulonglong),
            ("TimeStamp", ctypes.c_longlong),
            ("Guid", GUID),
            ("ClientContext", ctypes.c_ulong),
            ("Flags", ctypes.c_ulong),
        ]

    class EVENT_TRACE_PROPERTIES(ctypes.Structure):
        _fields_ = [
            ("Wnode", WNODE_HEADER),
            ("BufferSize_kb", ctypes.c_ulong),
            ("MinimumBuffers", ctypes.c_ulong),
            ("MaximumBuffers", ctypes.c_ulong),
            ("MaximumFileSize", ctypes.c_ulong),
            ("LogFileMode", ctypes.c_ulong),
            ("FlushTimer", ctypes.c_ulong),
            ("EnableFlags", ctypes.c_ulong),
            ("AgeLimit", ctypes.c_long),
            ("NumberOfBuffers", ctypes.c_ulong),
            ("FreeBuffers", ctypes.c_ulong),
            ("EventsLost", ctypes.c_ulong),
            ("BuffersWritten", ctypes.c_ulong),
            ("LogBuffersLost", ctypes.c_ulong),
            ("RealTimeBuffersLost", ctypes.c_ulong),
            ("LoggerThreadId", ctypes.wintypes.HANDLE),
            ("LogFileNameOffset", ctypes.c_ulong),
            ("LoggerNameOffset", ctypes.c_ulong),
        ]

    _advapi32 = ctypes.windll.advapi32  # type: ignore[attr-defined]
    _k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

    _advapi32.ControlTraceW.argtypes = [
        ctypes.c_ulonglong,
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
    ]
    _advapi32.ControlTraceW.restype = ctypes.c_ulong

    def _alloc_properties() -> ctypes.Array:  # type: ignore[type-arg]
        """Allocate EVENT_TRACE_PROPERTIES with trailing space for the name."""
        name_bytes = len(SESSION_NAME_W.encode("utf-16-le")) + 2
        total = ctypes.sizeof(EVENT_TRACE_PROPERTIES) + name_bytes
        buf = (ctypes.c_byte * total)()
        props = ctypes.cast(buf, ctypes.POINTER(EVENT_TRACE_PROPERTIES)).contents
        props.Wnode.BufferSize = total
        props.Wnode.Flags = WNODE_FLAG_TRACED_GUID
        props.Wnode.ClientContext = 1  # QPC timestamps
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
        props.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
        return buf

    def _stop_existing_session() -> None:
        """Stop a previously leaked session with the same name."""
        buf = _alloc_properties()
        _advapi32.ControlTraceW(
            ctypes.c_ulonglong(0), SESSION_NAME, buf, EVENT_TRACE_CONTROL_STOP,
        )

    def _is_suspect_assembly_path(path: str) -> bool:
        """Check if assembly path comes from temp/user directories."""
        lower = path.lower()
        return any(frag in lower for frag in SUSPECT_PATH_FRAGS)

    # . . . . . . . . . . . . . . . . -
    # ETW subprocess helper script.
    # The real-time ETW consumer uses a CFUNCTYPE callback that ctypes
    # allocates as a native trampoline. During CPython interpreter
    # shutdown, module globals (including the callback) get collected
    # while the ETW subsystem may still reference the trampoline,
    # causing an access violation. Running the consumer in a short-
    # lived subprocess isolates this entirely: the subprocess handles
    # its own teardown, and the main process never holds a dangling
    # callback pointer.
    # . . . . . . . . . . . . . . . . -
    _ETW_SUBPROCESS_SCRIPT = r'''
import ctypes, ctypes.wintypes, json, sys, threading, time

class GUID(ctypes.Structure):
    _fields_ = [("D1",ctypes.c_ulong),("D2",ctypes.c_ushort),
                 ("D3",ctypes.c_ushort),("D4",ctypes.c_ubyte*8)]

DOTNET_GUID = GUID(0xE13C0D23,0xCCBC,0x4E12,
    (ctypes.c_ubyte*8)(0x93,0x1B,0xD9,0xCC,0x2E,0xEE,0x27,0xE4))

class WNODE_HEADER(ctypes.Structure):
    _fields_ = [("BufferSize",ctypes.c_ulong),("ProviderId",ctypes.c_ulong),
        ("HistoricalContext",ctypes.c_ulonglong),("TimeStamp",ctypes.c_longlong),
        ("Guid",GUID),("ClientContext",ctypes.c_ulong),("Flags",ctypes.c_ulong)]

class EVENT_TRACE_PROPERTIES(ctypes.Structure):
    _fields_ = [("Wnode",WNODE_HEADER),("BufferSize_kb",ctypes.c_ulong),
        ("MinimumBuffers",ctypes.c_ulong),("MaximumBuffers",ctypes.c_ulong),
        ("MaximumFileSize",ctypes.c_ulong),("LogFileMode",ctypes.c_ulong),
        ("FlushTimer",ctypes.c_ulong),("EnableFlags",ctypes.c_ulong),
        ("AgeLimit",ctypes.c_long),("NumberOfBuffers",ctypes.c_ulong),
        ("FreeBuffers",ctypes.c_ulong),("EventsLost",ctypes.c_ulong),
        ("BuffersWritten",ctypes.c_ulong),("LogBuffersLost",ctypes.c_ulong),
        ("RealTimeBuffersLost",ctypes.c_ulong),
        ("LoggerThreadId",ctypes.wintypes.HANDLE),
        ("LogFileNameOffset",ctypes.c_ulong),("LoggerNameOffset",ctypes.c_ulong)]

class EVENT_HEADER(ctypes.Structure):
    _fields_ = [("Size",ctypes.c_ushort),("HeaderType",ctypes.c_ushort),
        ("Flags",ctypes.c_ushort),("EventProperty",ctypes.c_ushort),
        ("ThreadId",ctypes.c_ulong),("ProcessId",ctypes.c_ulong),
        ("TimeStamp",ctypes.c_longlong),("ProviderId",GUID),
        ("Ed_Id",ctypes.c_ushort),("Ed_Ver",ctypes.c_ubyte),
        ("Ed_Ch",ctypes.c_ubyte),("Ed_Lv",ctypes.c_ubyte),
        ("Ed_Op",ctypes.c_ubyte),("Ed_Task",ctypes.c_ushort),
        ("Ed_Kw",ctypes.c_ulonglong),("ActivityId",GUID)]

class ETW_BUFFER_CONTEXT(ctypes.Structure):
    _fields_ = [("ProcessorNumber",ctypes.c_ubyte),
        ("Alignment",ctypes.c_ubyte),("LoggerId",ctypes.c_ushort)]

class EVENT_RECORD(ctypes.Structure):
    _fields_ = [("EventHeader",EVENT_HEADER),("BufferContext",ETW_BUFFER_CONTEXT),
        ("ExtendedDataCount",ctypes.c_ushort),("UserDataLength",ctypes.c_ushort),
        ("ExtendedData",ctypes.c_void_p),("UserData",ctypes.c_void_p),
        ("UserContext",ctypes.c_void_p)]

EVENT_RECORD_CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.POINTER(EVENT_RECORD))

class EVENT_TRACE_LOGFILEW(ctypes.Structure):
    _fields_ = [("LogFileName",ctypes.c_wchar_p),("LoggerName",ctypes.c_wchar_p),
        ("CurrentTime",ctypes.c_longlong),("BuffersRead",ctypes.c_ulong),
        ("LogFileMode_union",ctypes.c_ulong),
        ("p1",ctypes.c_ulong),("p2",ctypes.c_ulong),("p3",ctypes.c_ulonglong),
        ("p4",ctypes.c_void_p),("p5",ctypes.c_ulong),("p6",ctypes.c_ulong),
        ("BufferSize2",ctypes.c_ulong),("Filled",ctypes.c_ulong),
        ("EventsLost2",ctypes.c_ulong),
        ("EventRecordCallback",EVENT_RECORD_CALLBACK),
        ("IsKernelTrace",ctypes.c_ulong),("Context",ctypes.c_void_p)]

adv = ctypes.windll.advapi32
k32 = ctypes.windll.kernel32
adv.StartTraceW.argtypes=[ctypes.POINTER(ctypes.c_ulonglong),ctypes.c_wchar_p,ctypes.c_void_p]
adv.StartTraceW.restype=ctypes.c_ulong
adv.EnableTraceEx2.argtypes=[ctypes.c_ulonglong,ctypes.POINTER(GUID),ctypes.c_ulong,
    ctypes.c_ubyte,ctypes.c_ulonglong,ctypes.c_ulonglong,ctypes.c_ulong,ctypes.c_void_p]
adv.EnableTraceEx2.restype=ctypes.c_ulong
adv.ControlTraceW.argtypes=[ctypes.c_ulonglong,ctypes.c_wchar_p,ctypes.c_void_p,ctypes.c_ulong]
adv.ControlTraceW.restype=ctypes.c_ulong
adv.OpenTraceW.argtypes=[ctypes.c_void_p]; adv.OpenTraceW.restype=ctypes.c_ulonglong
adv.ProcessTrace.argtypes=[ctypes.POINTER(ctypes.c_ulonglong),ctypes.c_ulong,ctypes.c_void_p,ctypes.c_void_p]
adv.ProcessTrace.restype=ctypes.c_ulong
adv.CloseTrace.argtypes=[ctypes.c_ulonglong]; adv.CloseTrace.restype=ctypes.c_ulong

SNAME = "SentinelDotNetTrace"
INVALID = 0xFFFFFFFFFFFFFFFF
window = float(sys.argv[1]) if len(sys.argv) > 1 else 3.0
collected = []

def alloc_props():
    nb = len((SNAME+"\0").encode("utf-16-le")) + 2
    total = ctypes.sizeof(EVENT_TRACE_PROPERTIES) + nb
    buf = (ctypes.c_byte * total)()
    p = ctypes.cast(buf, ctypes.POINTER(EVENT_TRACE_PROPERTIES)).contents
    p.Wnode.BufferSize = total
    p.Wnode.Flags = 0x20000
    p.Wnode.ClientContext = 1
    p.LogFileMode = 0x100
    p.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
    return buf

# Stop leaked session
adv.ControlTraceW(ctypes.c_ulonglong(0), SNAME, alloc_props(), 1)

sh = ctypes.c_ulonglong(0)
ret = adv.StartTraceW(ctypes.byref(sh), SNAME, alloc_props())
if ret == 183:
    adv.ControlTraceW(ctypes.c_ulonglong(0), SNAME, alloc_props(), 1)
    ret = adv.StartTraceW(ctypes.byref(sh), SNAME, alloc_props())
if ret != 0:
    print(json.dumps({"error": ret, "events": []}))
    sys.exit(0)

ret = adv.EnableTraceEx2(sh, ctypes.byref(DOTNET_GUID), 1, 4,
    ctypes.c_ulonglong(0x8), ctypes.c_ulonglong(0), 0, None)
if ret != 0:
    adv.ControlTraceW(sh, None, alloc_props(), 1)
    print(json.dumps({"error": ret, "events": []}))
    sys.exit(0)

def on_event(ev_ptr):
    try:
        ev = ev_ptr.contents
        pid = ev.EventHeader.ProcessId
        udlen = ev.UserDataLength
        strings = []
        if ev.UserData and udlen >= 2:
            raw = (ctypes.c_byte * udlen)()
            ctypes.memmove(raw, ev.UserData, udlen)
            blob = bytes(raw)
            decoded = blob.decode("utf-16-le", errors="replace")
            for part in decoded.split("\x00"):
                c = part.strip()
                if len(c) > 2:
                    strings.append(c)
        collected.append({"pid": pid, "strings": strings})
    except Exception:
        pass

cb = EVENT_RECORD_CALLBACK(on_event)
lf = EVENT_TRACE_LOGFILEW()
lf.LoggerName = SNAME
lf.LogFileName = None
lf.LogFileMode_union = 0x10000100
lf.EventRecordCallback = cb

th = adv.OpenTraceW(ctypes.byref(lf))
if th == INVALID:
    adv.ControlTraceW(sh, None, alloc_props(), 1)
    print(json.dumps({"error": -1, "events": []}))
    sys.exit(0)

ha = (ctypes.c_ulonglong * 1)(th)
def consume():
    adv.ProcessTrace(ha, 1, None, None)

w = threading.Thread(target=consume, daemon=True)
w.start()
time.sleep(window)

adv.EnableTraceEx2(sh, ctypes.byref(DOTNET_GUID), 0, 0, 0, 0, 0, None)
adv.CloseTrace(th)
w.join(timeout=5.0)
adv.ControlTraceW(sh, None, alloc_props(), 1)

print(json.dumps({"error": 0, "events": collected}))
# Use os._exit to skip interpreter teardown and avoid the access
# violation that occurs when ctypes CFUNCTYPE trampolines are freed
# while the ETW subsystem still references them.
import os; os._exit(0)
'''

    def scan_etw_dotnet(window_sec: float = 3.0) -> list[Finding]:
        """Consume DotNETRuntime loader events for a short window.

        Runs the ETW consumer in a subprocess to isolate ctypes callback
        lifetime issues from the main process. Flags assemblies loaded
        from memory (no file path) or from temp/user directories.
        Requires admin privileges.
        """
        import json as _json

        findings: list[Finding] = []
        timeout = window_sec + 15.0

        try:
            result = subprocess.run(
                [sys.executable, "-c", _ETW_SUBPROCESS_SCRIPT, str(window_sec)],
                capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            log.warning("ETW subprocess timed out after %.0fs", timeout)
            # Clean up leaked session
            _stop_existing_session()
            return findings
        except FileNotFoundError:
            log.warning("Python interpreter not found for ETW subprocess")
            return findings

        if not result.stdout.strip():
            if result.returncode == 5 or "access" in result.stderr.lower():
                findings.append(Finding(
                    module=MODULE_NAME,
                    title="ETW trace requires elevation",
                    severity="info",
                    detail="Cannot start ETW session without admin privileges.",
                    evidence="StartTraceW returned ERROR_ACCESS_DENIED (5)",
                    mitre_id=MITRE_REFLECTIVE_LOAD,
                ))
            return findings

        try:
            data = _json.loads(result.stdout)
        except _json.JSONDecodeError:
            log.debug("ETW subprocess returned non-JSON: %s", result.stdout[:200])
            return findings

        err = data.get("error", 0)
        if err == ERROR_ACCESS_DENIED:
            findings.append(Finding(
                module=MODULE_NAME,
                title="ETW trace requires elevation",
                severity="info",
                detail="Cannot start ETW session without admin privileges.",
                evidence=f"StartTraceW returned error {err}",
                mitre_id=MITRE_REFLECTIVE_LOAD,
            ))
            return findings
        if err != 0:
            log.warning("ETW subprocess reported error %d", err)
            return findings

        # Analyze collected events
        for entry in data.get("events", []):
            pid = entry.get("pid", 0)
            strings = entry.get("strings", [])
            has_path = False
            assembly_name = ""
            assembly_path = ""

            for s in strings:
                if isinstance(s, str):
                    if "\\" in s or "/" in s:
                        assembly_path = s
                        has_path = True
                    elif not assembly_name and len(s) > 2:
                        assembly_name = s

            label = assembly_name or assembly_path or "(unknown)"

            if not has_path:
                findings.append(Finding(
                    module=MODULE_NAME,
                    title="In-memory .NET assembly load",
                    severity="high",
                    detail=(
                        f"Assembly '{label}' loaded without a file path "
                        f"in PID {pid}. This is consistent with reflective "
                        f"loading (e.g., Assembly.Load(byte[]))."
                    ),
                    evidence=f"pid={pid} assembly={label} path=<none>",
                    mitre_id=MITRE_REFLECTIVE_LOAD,
                    pid=int(pid),
                ))
            elif _is_suspect_assembly_path(assembly_path):
                findings.append(Finding(
                    module=MODULE_NAME,
                    title=".NET assembly loaded from suspicious path",
                    severity="medium",
                    detail=(
                        f"Assembly '{label}' loaded from '{assembly_path}' "
                        f"in PID {pid}. Temp/user directories are common "
                        f"staging locations for fileless payloads."
                    ),
                    evidence=f"pid={pid} path={assembly_path}",
                    mitre_id=MITRE_REFLECTIVE_LOAD,
                    path=assembly_path,
                    pid=int(pid),
                ))

        return findings


# ===================================================================
# 2. PowerShell script block logging (Event ID 4104)
# ===================================================================

def scan_powershell_scriptblocks(max_events: int = 200) -> list[Finding]:
    """Parse Event ID 4104 from the PowerShell Operational log.

    Uses wevtutil (built-in) to avoid third-party dependencies.
    Flags blocks containing known fileless/offensive indicators.
    """
    findings: list[Finding] = []
    if not IS_WIN:
        return findings

    cmd = [
        "wevtutil", "qe",
        "Microsoft-Windows-PowerShell/Operational",
        "/q:*[System[(EventID=4104)]]",
        "/f:RenderedXml",
        f"/c:{max_events}",
        "/rd:true",
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30,
        )
    except FileNotFoundError:
        log.warning("wevtutil not found; skipping script block scan")
        return findings
    except subprocess.TimeoutExpired:
        log.warning("wevtutil timed out after 30s")
        return findings

    if result.returncode != 0:
        if "access" in result.stderr.lower() or "denied" in result.stderr.lower():
            findings.append(Finding(
                module=MODULE_NAME,
                title="Script block log access denied",
                severity="info",
                detail="Elevation required to read PowerShell Operational log.",
                evidence=result.stderr.strip()[:200],
                mitre_id=MITRE_POWERSHELL,
            ))
        return findings

    # wevtutil output is not valid XML as a whole document; each Event
    # element is separate. Wrap in a root element for parsing.
    xml_text = "<Root>" + result.stdout + "</Root>"
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        log.debug("failed to parse wevtutil XML output")
        return findings

    ns = {
        "e": "http://schemas.microsoft.com/win/2004/08/events/event",
        "r": "http://schemas.microsoft.com/win/2004/08/events/rendering",
    }

    for event in root:
        # Find ScriptBlockText in EventData
        script_text = ""
        for data_el in event.iter():
            if data_el.attrib.get("Name") == "ScriptBlockText" and data_el.text:
                script_text = data_el.text
                break
        if not script_text:
            # Try unnamespaced Data elements
            for data_el in event.iter("Data"):
                if data_el.attrib.get("Name") == "ScriptBlockText" and data_el.text:
                    script_text = data_el.text
                    break
        if not script_text:
            continue

        matched: list[str] = []
        upper_text = script_text.upper()
        for indicator in PS_INDICATORS:
            if indicator.upper() in upper_text:
                matched.append(indicator)

        if matched:
            # Extract a snippet for evidence (first 300 chars)
            snippet = script_text[:300].replace("\n", " ").strip()
            findings.append(Finding(
                module=MODULE_NAME,
                title="Suspicious PowerShell script block",
                severity="high",
                detail=(
                    f"Script block contains {len(matched)} indicator(s): "
                    f"{', '.join(matched)}. This pattern is consistent with "
                    f"fileless execution or offensive tooling."
                ),
                evidence=f"indicators={matched} snippet={snippet}",
                mitre_id=MITRE_POWERSHELL,
            ))

    return findings


# ===================================================================
# 3. Process injection detection (unbacked exec + CreateRemoteThread)
# ===================================================================

# Thread enumeration via CreateToolhelp32Snapshot
SKIP_PIDS: set[int] = {0, 4}

if IS_WIN:
    TH32CS_SNAPTHREAD: int = 0x00000004
    THREAD_QUERY_INFORMATION: int = 0x0040
    THREAD_QUERY_LIMITED_INFORMATION: int = 0x0800

    class THREADENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.wintypes.DWORD),
            ("cntUsage", ctypes.wintypes.DWORD),
            ("th32ThreadID", ctypes.wintypes.DWORD),
            ("th32OwnerProcessID", ctypes.wintypes.DWORD),
            ("tpBasePri", ctypes.c_long),
            ("tpDeltaPri", ctypes.c_long),
            ("dwFlags", ctypes.wintypes.DWORD),
        ]

    _k32.CreateToolhelp32Snapshot.argtypes = [
        ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
    ]
    _k32.CreateToolhelp32Snapshot.restype = ctypes.wintypes.HANDLE

    _k32.Thread32First.argtypes = [
        ctypes.wintypes.HANDLE, ctypes.POINTER(THREADENTRY32),
    ]
    _k32.Thread32First.restype = ctypes.wintypes.BOOL

    _k32.Thread32Next.argtypes = [
        ctypes.wintypes.HANDLE, ctypes.POINTER(THREADENTRY32),
    ]
    _k32.Thread32Next.restype = ctypes.wintypes.BOOL

    _k32.OpenThread.argtypes = [
        ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD,
    ]
    _k32.OpenThread.restype = ctypes.wintypes.HANDLE

    _k32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
    _k32.CloseHandle.restype = ctypes.wintypes.BOOL

    # NtQueryInformationThread for start address
    _ntdll = ctypes.windll.ntdll  # type: ignore[attr-defined]
    _ntdll.NtQueryInformationThread.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    _ntdll.NtQueryInformationThread.restype = ctypes.c_long

    ThreadQuerySetWin32StartAddress = 9

    # Memory region constants (reused from sentinel.memory)
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80
    MEM_COMMIT = 0x1000
    MEM_PRIVATE = 0x20000
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010

    EXEC_PROTECTIONS = {
        PAGE_EXECUTE, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    }

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

    _k32.VirtualQueryEx.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION),
        ctypes.c_size_t,
    ]
    _k32.VirtualQueryEx.restype = ctypes.c_size_t

    _k32.OpenProcess.argtypes = [
        ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD,
    ]
    _k32.OpenProcess.restype = ctypes.wintypes.HANDLE

    def _get_unbacked_exec_ranges(pid: int) -> list[tuple[int, int]]:
        """Return list of (start, end) for MEM_PRIVATE executable regions."""
        handle = _k32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid,
        )
        if not handle:
            return []
        ranges: list[tuple[int, int]] = []
        try:
            mbi = MEMORY_BASIC_INFORMATION()
            addr = 0
            while True:
                ret = _k32.VirtualQueryEx(
                    handle, ctypes.c_void_p(addr),
                    ctypes.byref(mbi), _MBI_SIZE,
                )
                if ret == 0:
                    break
                if (
                    mbi.State == MEM_COMMIT
                    and mbi.Type == MEM_PRIVATE
                    and mbi.Protect in EXEC_PROTECTIONS
                ):
                    base = mbi.BaseAddress or 0
                    ranges.append((base, base + mbi.RegionSize))
                next_addr = (addr or 0) + mbi.RegionSize
                if next_addr <= addr:
                    break
                addr = next_addr
        finally:
            _k32.CloseHandle(handle)
        return ranges

    def _get_thread_start_addresses(pid: int) -> list[tuple[int, int]]:
        """Return list of (thread_id, start_address) for threads in a process."""
        snap = _k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        if snap == ctypes.wintypes.HANDLE(-1).value:
            return []
        results: list[tuple[int, int]] = []
        try:
            te = THREADENTRY32()
            te.dwSize = ctypes.sizeof(THREADENTRY32)
            if not _k32.Thread32First(snap, ctypes.byref(te)):
                return results
            while True:
                if te.th32OwnerProcessID == pid:
                    tid = te.th32ThreadID
                    h_thread = _k32.OpenThread(
                        THREAD_QUERY_LIMITED_INFORMATION, False, tid,
                    )
                    if h_thread:
                        start_addr = ctypes.c_void_p(0)
                        ret_len = ctypes.c_ulong(0)
                        status = _ntdll.NtQueryInformationThread(
                            h_thread,
                            ThreadQuerySetWin32StartAddress,
                            ctypes.byref(start_addr),
                            ctypes.sizeof(start_addr),
                            ctypes.byref(ret_len),
                        )
                        _k32.CloseHandle(h_thread)
                        if status >= 0 and start_addr.value:
                            results.append((tid, start_addr.value))
                if not _k32.Thread32Next(snap, ctypes.byref(te)):
                    break
        finally:
            _k32.CloseHandle(snap)
        return results

    def scan_process_injection() -> list[Finding]:
        """Detect CreateRemoteThread injection by correlating thread start
        addresses with unbacked executable memory regions."""
        findings: list[Finding] = []
        for proc in psutil.process_iter(["pid", "name"]):
            pid = proc.info["pid"]
            if pid in SKIP_PIDS:
                continue
            name = proc.info["name"] or f"<pid:{pid}>"
            try:
                unbacked = _get_unbacked_exec_ranges(pid)
                if not unbacked:
                    continue

                threads = _get_thread_start_addresses(pid)
                for tid, start in threads:
                    for rng_start, rng_end in unbacked:
                        if rng_start <= start < rng_end:
                            findings.append(Finding(
                                module=MODULE_NAME,
                                title="CreateRemoteThread injection detected",
                                severity="critical",
                                detail=(
                                    f"Thread {tid} in '{name}' (PID {pid}) "
                                    f"starts at 0x{start:x}, which falls in "
                                    f"an unbacked executable region "
                                    f"(0x{rng_start:x}-0x{rng_end:x}). "
                                    f"This is a strong indicator of injected code."
                                ),
                                evidence=(
                                    f"pid={pid} tid={tid} "
                                    f"start=0x{start:x} "
                                    f"region=0x{rng_start:x}-0x{rng_end:x}"
                                ),
                                mitre_id=MITRE_CREATE_REMOTE_THREAD,
                                pid=pid,
                            ))
                            break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as exc:
                log.debug("injection scan pid %d: %s", pid, exc)
        return findings
else:
    def scan_process_injection() -> list[Finding]:
        return []


# ===================================================================
# 4. CLR loading in unusual processes
# ===================================================================

def scan_clr_in_unusual_processes() -> list[Finding]:
    """Check for CLR DLLs loaded in processes that normally never use .NET."""
    findings: list[Finding] = []
    if not IS_WIN:
        return findings

    for proc in psutil.process_iter(["pid", "name"]):
        pid = proc.info["pid"]
        name = (proc.info["name"] or "").lower()
        if name not in NON_DOTNET_PROCESSES:
            continue
        try:
            mmaps = proc.memory_maps(grouped=False)
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            continue
        loaded_clr: list[str] = []
        for mmap in mmaps:
            dll_name = Path(mmap.path).name.lower() if mmap.path else ""
            if dll_name in CLR_DLLS:
                loaded_clr.append(mmap.path)
        if loaded_clr:
            findings.append(Finding(
                module=MODULE_NAME,
                title=f"CLR loaded in unexpected process: {name}",
                severity="medium",
                detail=(
                    f"Process '{name}' (PID {pid}) has loaded CLR DLLs: "
                    f"{', '.join(Path(p).name for p in loaded_clr)}. "
                    f"This process does not normally use .NET and may "
                    f"indicate CLR-based injection (execute-assembly, "
                    f"inline .NET execution)."
                ),
                evidence=f"pid={pid} name={name} clr_dlls={loaded_clr}",
                mitre_id=MITRE_DOTNET_EXEC,
                pid=pid,
            ))
    return findings


# ===================================================================
# Public API
# ===================================================================

@dataclass
class FilelessReport:
    """Aggregated report from all fileless detection checks."""
    findings: list[Finding] = field(default_factory=list)
    etw_events: int = 0
    scriptblocks_scanned: int = 0
    processes_scanned: int = 0
    errors: int = 0

    @property
    def clean(self) -> bool:
        return len(self.findings) == 0


def scan(
    etw_window_sec: float = 3.0,
    max_scriptblocks: int = 200,
    skip_etw: bool = False,
) -> FilelessReport:
    """Run all fileless malware detection checks.

    Args:
        etw_window_sec: Seconds to collect ETW loader events.
        max_scriptblocks: Max Event ID 4104 entries to parse.
        skip_etw: Skip the ETW trace (useful in non-admin context).

    Returns:
        FilelessReport with aggregated findings.
    """
    report = FilelessReport()
    if not IS_WIN:
        return report

    # 1. ETW .NET assembly loading
    if not skip_etw:
        try:
            etw_findings = scan_etw_dotnet(window_sec=etw_window_sec)
            report.findings.extend(etw_findings)
        except Exception as exc:
            log.warning("ETW scan failed: %s", exc)
            report.errors += 1

    # 2. PowerShell script block logging
    try:
        ps_findings = scan_powershell_scriptblocks(max_events=max_scriptblocks)
        report.findings.extend(ps_findings)
    except Exception as exc:
        log.warning("PowerShell scan failed: %s", exc)
        report.errors += 1

    # 3. Process injection (unbacked exec + CreateRemoteThread)
    try:
        inj_findings = scan_process_injection()
        report.findings.extend(inj_findings)
    except Exception as exc:
        log.warning("injection scan failed: %s", exc)
        report.errors += 1

    # 4. CLR in unusual processes
    try:
        clr_findings = scan_clr_in_unusual_processes()
        report.findings.extend(clr_findings)
    except Exception as exc:
        log.warning("CLR scan failed: %s", exc)
        report.errors += 1

    return report


def run(quick: bool = True) -> list[Finding]:
    """Entry point matching the sentinel module interface.

    Args:
        quick: if True, use a shorter ETW window (1s vs 3s).

    Returns:
        list of Finding objects from all fileless checks.
    """
    if not IS_WIN:
        return []
    window = 1.0 if quick else 3.0
    report = scan(etw_window_sec=window)
    return report.findings