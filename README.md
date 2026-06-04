# sentinel

Host-based endpoint threat detection focused on RAT identification, spyware
indicators, and network anomaly detection. Runs on Windows and Linux.
Python 3.10+.

Sentinel is a defensive tool built for incident responders and system
administrators who need to answer one question fast: is this host compromised?
It inspects running processes, network connections, persistence mechanisms,
and local certificates to surface indicators of compromise without requiring
cloud connectivity or a full EDR deployment.

This is not a replacement for production EDR. It is a triage tool -- something
you drop onto a suspect machine and run. It exits non-zero when it finds
high-severity indicators, making it usable in scripts and CI pipelines.


## Features

- **Process integrity scanning** -- Authenticode signature verification on
  Windows, ELF heuristics on Linux. Flags unsigned binaries, executables
  running from temp directories, known RAT process names (DarkComet, njRAT,
  AsyncRAT, Cobalt Strike beacon, Sliver, Meterpreter, and ~30 others),
  orphaned processes, and DLL injection indicators.

- **Network connection analysis** -- Enumerates established TCP connections,
  flags traffic to known C2 ports (4444, 5555, 31337, etc.), resolves remote
  IPs to ASN/hostname via Team Cymru DNS lookups, and identifies unsigned
  processes making outbound connections.

- **C2 beaconing detection** -- Samples connections over a configurable time
  window, computes inter-connection intervals, and flags regular-interval
  patterns with low jitter (coefficient of variation below 15%). Catches
  the callback timing that most RATs and implants use.

- **Persistence mechanism hunting** -- On Windows: Run/RunOnce registry keys,
  Winlogon Shell/Userinit tampering, Image File Execution Options debugger
  hijacking, AppInit_DLLs, WMI event subscriptions, scheduled tasks, startup
  folder contents, and services running from non-standard paths. On Linux:
  crontabs (user and system), systemd units, shell RC file injection, and
  init.d scripts.

- **Certificate store audit** -- Inspects the local certificate store for
  untrusted roots, expired certificates, and certificates with unusual
  properties that might indicate MITM proxying.

- **ARP anomaly detection** -- Checks the local ARP table for duplicate MAC
  addresses, gateway spoofing, and other indicators of ARP poisoning.

- **Consolidated reporting** -- JSON or plain text output with findings sorted
  by severity. Exit code 1 on high/critical findings for scripted use.


## Quick start

```
git clone <repo-url> sentinel
cd sentinel
pip install -e .
```

Dependencies (installed automatically):

- psutil
- requests

Run a quick scan:

```
python -m sentinel.scanner --quick
```

Run a full scan (includes slower checks like beaconing detection):

```
python -m sentinel.scanner --full
```

Write results to a file:

```
python -m sentinel.scanner --full -o report.json --json
```

Individual modules can be run standalone for targeted checks:

```
python -m sentinel.scanner -m net_scan
python -m sentinel.scanner -m proc_integrity persistence
```

List available modules:

```
python -m sentinel.scanner --list-modules
```


## Usage examples

### Triage a suspect Windows host

```
python -m sentinel.scanner --full --json -o triage.json
```

This runs every module including beaconing analysis and persistence hunting.
Takes 1-2 minutes depending on the number of running processes and network
connections. Review `triage.json` or pipe it through jq:

```
type triage.json | python -m json.tool
```

### Quick network check

```
python -m sentinel.scanner -m net_scan
```

Enumerates TCP connections, flags C2 port hits, checks process signatures,
and resolves ASN info. Finishes in seconds.

### Beaconing detection (standalone)

The network module can be imported directly for scripted use:

```python
from sentinel.modules.net_scan import analyze

result = analyze(
    check_beaconing=True,
    beacon_duration=120.0,
    resolve_asns=True,
)

for beacon in result.beacon_candidates:
    print(f"{beacon.process_name} -> {beacon.remote_addr}:{beacon.remote_port}")
    print(f"  interval: {beacon.interval_sec}s, jitter: {beacon.jitter_pct}%")
```

### Process scan from a script

```python
from sentinel.modules.proc_integrity import scan_processes

report = scan_processes(check_signatures=True)
for finding in report.findings:
    print(f"[{finding.kind}] {finding.name} (PID {finding.pid})")
    print(f"  {finding.detail}")

sys.exit(0 if report.clean else 1)
```

### Persistence audit with JSON output

```
python -m sentinel.scanner -m persistence --json
```

On Windows this queries the registry, scheduled tasks, WMI subscriptions,
startup folders, and services. On Linux it checks crontabs, systemd units,
shell profiles, and init scripts.


## Methodology

### Process integrity (T1055, T1036)

Every running process is checked against several indicators:

1. **Signature verification.** On Windows, Authenticode verification via
   WinVerifyTrust. Unsigned binaries making network connections or running
   from user-writable paths are flagged. On Linux, this falls back to
   checking for known ELF signature sections and whether the binary lives
   in a package-managed path.

2. **Execution path analysis.** Processes running from temp directories,
   AppData\Roaming, the Recycle Bin, ProgramData, or other non-standard
   locations are flagged. These are common staging directories for
   first-stage droppers.

3. **RAT process name matching.** The process name is checked against a
   list of ~35 known RAT families. This catches operators who do not rename
   their binaries, which is more common than you would expect on commodity
   RAT deployments.

4. **Parent-child validation.** Orphaned processes -- where the parent PID
   no longer exists -- are flagged. On Linux, zombie processes and PIDs
   missing from /proc are also reported.

5. **DLL/SO injection indicators.** On Windows, the loaded modules of each
   process are inspected for DLLs loaded from suspicious paths (temp dirs,
   user-writable locations outside the binary's own directory). On Linux,
   /proc/[pid]/maps is checked for shared objects loaded from /tmp or
   /dev/shm.


### Network analysis (T1071, T1573)

The network module works in two phases:

**Phase 1 -- Snapshot.** All established TCP connections are enumerated via
psutil. Each connection is enriched with:

- Process name and executable path
- Signature status of the owning process
- Whether the remote port matches a known C2 port list
- ASN/hostname of the remote IP (Team Cymru DNS or reverse DNS)

Connections from unsigned processes to external IPs are flagged. Connections
to known C2 ports get a separate high-severity flag.

**Phase 2 -- Beaconing (optional, --full mode).** The scanner polls TCP
connections at a configurable rate (default 2s) over a configurable window
(default 60s). For each unique (remote_addr, remote_port, pid) tuple, it
records timestamps and computes:

- Mean interval between connections
- Jitter as coefficient of variation (stddev / mean)

Tuples with 4+ samples, intervals above 1 second, and jitter below 15%
are reported as beaconing candidates. This catches the regular callback
timing used by most C2 frameworks -- Cobalt Strike, Sliver, Havoc, and
commodity RATs all exhibit this pattern unless the operator has configured
heavy jitter.


### Persistence hunting (T1547, T1053, T1546)

Platform-specific checks for common persistence techniques:

**Windows:**
- Registry Run/RunOnce keys (HKLM and HKCU)
- Winlogon Shell and Userinit values (flags non-default entries)
- Image File Execution Options Debugger keys (used for binary hijacking)
- AppInit_DLLs (loaded into every user-mode process)
- Scheduled tasks with non-Microsoft authors
- WMI event subscriptions (EventFilter, CommandLineEventConsumer,
  ActiveScriptEventConsumer)
- Startup folder contents
- Services running from paths outside System32, Program Files

**Linux:**
- User and system crontabs, cron.d/daily/hourly directories
- Systemd user and system units (.service and .timer files)
- Shell RC files (.bashrc, .zshrc, .profile) scanned for suspicious
  patterns (curl pipes, base64, eval, /dev/tcp, reverse shells)
- /etc/init.d scripts


### Certificate audit

Enumerates the local certificate store and flags:
- Root CA certificates not in a known-good baseline
- Expired or not-yet-valid certificates
- Certificates with unusual key usage or SAN configurations
  that may indicate MITM proxy installations


### ARP anomaly detection

Parses the local ARP table and flags:
- Multiple IPs mapping to the same MAC address (potential ARP spoofing)
- Gateway MAC address changes between scans
- Incomplete ARP entries for hosts that should be reachable


## Platform support

| Check | Windows | Linux |
|-------|---------|-------|
| Process signatures | Authenticode (WinVerifyTrust) | ELF heuristics |
| Process path analysis | Yes | Yes |
| RAT name matching | Yes | Yes |
| DLL/SO injection | Memory-mapped DLL inspection | /proc/[pid]/maps |
| Network connections | psutil TCP enumeration | psutil TCP enumeration |
| Beaconing detection | Yes | Yes |
| Persistence: registry | Run keys, Winlogon, IFEO, AppInit | N/A |
| Persistence: tasks | Scheduled tasks, WMI | Crontabs, systemd |
| Persistence: services | Win32 services | init.d |
| Persistence: startup | Startup folder, shell RC | Shell RC |
| Certificate audit | Windows cert store | System CA bundle |
| ARP anomalies | arp -a parsing | /proc/net/arp |


## Project layout

```
sentinel/
    __init__.py
    scanner.py          # main orchestrator, CLI entry point
    modules/
        net_scan.py     # network connection analysis + beaconing
        proc_integrity.py   # process signature and integrity checks
        persistence.py  # persistence mechanism hunting
        cert_audit.py   # certificate store audit
        arp_anomaly.py  # ARP table anomaly detection
pyproject.toml
README.md
```


## Limitations

- Beaconing detection requires the scanner to run for the full observation
  window. A 60-second default means the scan blocks for at least that long
  in full mode.

- Process signature checks on Linux are heuristic-based. There is no
  universal code-signing standard on Linux, so false positives are expected
  for legitimate unsigned binaries.

- The RAT name list is static. Rename the binary and this check is
  bypassed. It catches lazy deployments, not targeted operations.

- Requires elevated privileges for full coverage. Without admin/root,
  some processes will be inaccessible and some persistence locations
  unreadable.

- ASN resolution depends on DNS being functional. On a compromised host
  with tampered DNS, the results may be unreliable.


## License

All Rights Reserved. Proprietary -- no forking, no redistribution.
