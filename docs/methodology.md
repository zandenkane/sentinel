# Sentinel Detection Methodology

MIT License. See [LICENSE](../LICENSE) for details.

## 1. Overview

Sentinel is a host-based threat detection tool that runs five scanning modules against a live
endpoint and produces a consolidated findings report. Each module targets a different attack
surface. This document describes the detection logic, thresholds, and operational procedures
for every module, with explicit mapping to MITRE ATT&CK technique identifiers.

The scanner assigns every finding a severity level from a five-tier model:

| Level    | Meaning                                                    |
|----------|------------------------------------------------------------|
| CRITICAL | Active compromise indicator. immediate response required |
| HIGH     | Strong IOC. triage within one hour                       |
| MEDIUM   | Anomaly worth investigating. triage within 24 hours      |
| LOW      | Weak signal. log and correlate with other findings       |
| INFO     | Baseline data point. no direct threat                    |

The main scanner exits with code 1 if any HIGH or CRITICAL finding is present, and code 0
otherwise. This makes it straightforward to gate CI/CD pipelines or cron jobs on scan results.

. -

## 2. Module: Network Scan

### 2.1 Connection Enumeration

The network module pulls all TCP connections in ESTABLISHED state via the OS process table.
For each connection it records:

- PID and process name
- Full executable path of the owning process
- Local address and port
- Remote address and port
- Connection status

Private ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, ::1) are tagged
as "private" during ASN resolution and excluded from external reputation checks.

### 2.2 C2 Port Detection

**MITRE ATT&CK: T1571 (Non-Standard Port)**

The module maintains a static list of ports historically tied to command-and-control
frameworks and RAT families:

| Port  | Association                        |
|-------|------------------------------------|
| 4444  | Metasploit default handler         |
| 5555  | Android debug bridge, various RATs |
| 6666  | IRC-based botnets                  |
| 1177  | DarkComet                          |
| 3127  | MyDoom                             |
| 9999  | Various C2 frameworks              |
| 31337 | Back Orifice, "eleet" convention   |

Any ESTABLISHED connection to a remote port in this set triggers an immediate finding. The
finding includes the process name, PID, full executable path, remote address, and resolved
hostname or ASN hint.

Severity assignment:

- If the owning process is unsigned or runs from a temp directory: **CRITICAL**
- If the owning process is signed but the port match is present: **HIGH**

### 2.3 Untrusted Process Flagging

**MITRE ATT&CK: T1036.005 (Masquerading: Match Legitimate Name or Location)**

Every connection's owning process is checked against a trust model:

1. Is the executable path inside a known system directory?
   - Windows: `\Windows\`, `\Program Files\`, `\Program Files (x86)\`,
     `\ProgramData\Microsoft\`, `\WindowsApps\`
   - Linux: `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/bin`, `/sbin`
2. If not in a trusted directory, is the binary signed?
   - Windows: PowerShell `Get-AuthenticodeSignature` with a 5-second timeout
   - Linux: ELF header scan for signature sections (heuristic)

A process that fails both checks is flagged. Additional temp-directory markers escalate the
severity:

- `temp`, `tmp`, `appdata\local\temp`, `/tmp` in the path: **HIGH**
- Untrusted but not in a temp path: **MEDIUM**
- No executable path available (process exited or access denied): **LOW**

### 2.4 Beacon Detection

**MITRE ATT&CK: T1071.001 (Application Layer Protocol: Web Protocols),
T1095 (Non-Application Layer Protocol),
T1573.001 (Encrypted Channel: Symmetric Cryptography),
T1573.002 (Encrypted Channel: Asymmetric Cryptography)**

C2 implants phone home on a regular interval (beaconing). Even with jitter applied, the
statistical regularity is detectable over a sufficient observation window.

The detection algorithm:

```
procedure detect_beaconing(duration, poll_rate):
    seen = {}  // key: (remote_ip, remote_port, pid) -> list of timestamps
    deadline = now() + duration

    while now() < deadline:
        for conn in established_tcp_connections():
            key = (conn.remote_ip, conn.remote_port, conn.pid)
            seen[key].append(current_time())
        sleep(min(poll_rate, time_remaining))

    for key, timestamps in seen:
        // Deduplicate observations within 0.5 second windows
        deduped = collapse(timestamps, threshold=0.5)

        if len(deduped) < 4:       // MIN_BEACON_SAMPLES
            skip

        intervals = pairwise_differences(deduped)
        avg = mean(intervals)

        if avg < 1.0 seconds:
            skip                   // too fast to be meaningful beaconing

        std = standard_deviation(intervals)
        jitter = std / avg         // coefficient of variation (CV)

        if jitter <= 0.15:         // BEACON_JITTER_THRESHOLD
            flag as beacon candidate
```

Key parameters:

| Parameter              | Value | Rationale                                     |
|------------------------|-------|-----------------------------------------------|
| MIN_BEACON_SAMPLES     | 4     | Need enough data points for statistical test   |
| BEACON_JITTER_THRESHOLD| 0.15  | 15% CV catches most C2 defaults (5-10% jitter)|
| Minimum avg interval   | 1.0s  | Filters out normal polling like NTP, heartbeat |
| Dedup window           | 0.5s  | Collapses multiple observations per poll cycle |

Default observation duration is 60 seconds with a 2-second poll rate, yielding up to 30
sample points per connection. In full-scan mode, the duration extends to capture slower
beacons.

Severity assignment for beacon candidates:

- CV <= 5% (very regular): **CRITICAL** .  almost certainly automated
- CV between 5% and 10%: **HIGH**
- CV between 10% and 15%: **MEDIUM**. could be legitimate polling

### 2.5 ASN Resolution

Each unique remote IP gets a reverse DNS lookup via `socket.gethostbyaddr()`. Results are
cached per-scan to avoid redundant lookups. The resolved hostname or ASN hint is attached
to every connection record and included in findings for analyst triage.

. -

## 3. Module: Process Integrity

### 3.1 Authenticode Signature Verification (Windows)

**MITRE ATT&CK: T1036.001 (Masquerading: Invalid Code Signature),
T1553.002 (Subvert Trust Controls: Code Signing)**

On Windows, the module calls `WinVerifyTrust` via ctypes to check embedded Authenticode
signatures. The verification flow:

```
procedure verify_binary(filepath):
    result = WinVerifyTrust(
        action = WINTRUST_ACTION_GENERIC_VERIFY_V2,
        ui     = WTD_UI_NONE,
        choice = WTD_CHOICE_FILE,
        revoke = WTD_REVOKE_NONE,
        state  = WTD_STATEACTION_VERIFY
    )

    if result == 0:
        return SIGNED    // embedded Authenticode valid

    if result == TRUST_E_NOSIGNATURE (0x800B0100):
        // No embedded sig. try Windows catalog verification
        return verify_via_catalog(filepath)

    return UNSIGNED      // signature present but invalid
```

Catalog verification handles OS-shipped binaries (like cmd.exe, notepad.exe) that are
not individually signed but are covered by a Windows catalog file:

1. Acquire a catalog admin context via `CryptCATAdminAcquireContext`
2. Open the target file with `CreateFileW` (GENERIC_READ, FILE_SHARE_READ)
3. Compute the file hash with `CryptCATAdminCalcHashFromFileHandle`
4. Search all installed catalogs for that hash with `CryptCATAdminEnumCatalogFromHash`
5. If a matching catalog entry is found, the binary is considered signed

On Linux, the module performs a heuristic ELF check, scanning the first 4 MB of the binary
for signature-related sections (`.note.gnu.build-id`, `Signature` markers). This is a
rough approximation since Linux lacks a unified code-signing infrastructure.

An unsigned binary running with network connections is a strong IOC:

- Unsigned + temp directory + network connection: **CRITICAL**
- Unsigned + non-standard location: **HIGH**
- Unsigned + standard location (unusual but possible): **MEDIUM**

### 3.2 Known RAT Process Name Matching

**MITRE ATT&CK: T1059.001 (Command and Scripting Interpreter: PowerShell),
T1059.003 (Command and Scripting Interpreter: Windows Command Shell)**

The module maintains a list of 38+ known RAT and C2 framework process names:

- Commodity RATs: DarkComet, njRAT, NanoCore, QuasarRAT, AsyncRAT, Remcos, Orcus, LimeRAT,
  Revenge-RAT, Adwind, PoisonIvy, Gh0st, BlackShades, CyberGate, Xtreme, SpyNet,
  Luminosity, Imminent, WarZone, dcRAT, Venom
- Red team tools: Havoc, Cobalt Strike (beacon), Meterpreter, Pupy, Empire, Covenant,
  Sliver, Brute Ratel
- Legacy: NetBus, SubSeven, Back Orifice, BO2K, XtremeRAT, XpertRAT, PandoRAT, Babylon

Matching is case-insensitive with `.exe` and `.bin` extensions stripped before comparison.
A substring match is used (e.g., "asyncrat_loader.exe" matches "asyncrat").

Any match: **CRITICAL**. the process name alone is a high-confidence IOC.

### 3.3 Suspicious Execution Path Analysis

**MITRE ATT&CK: T1204.002 (User Execution: Malicious File),
T1036.005 (Masquerading: Match Legitimate Name or Location)**

Executables running from certain filesystem locations are inherently suspect because
attackers stage payloads in writable, low-visibility directories:

| Path fragment              | Why it matters                                 |
|----------------------------|------------------------------------------------|
| `/temp/` or `/tmp/`        | Common staging directory for droppers          |
| `/appdata/local/temp`      | User temp. frequent malware delivery path    |
| `/appdata/roaming/`        | User roaming profile. persistence location   |
| `/public/`                 | Shared user directory. world-writable         |
| `/users/default/`          | Default profile. rarely used by legitimate sw|
| `/windows/debug/`          | Debug dump directory. writable by most users |
| `/$recycle` or `/recycle`  | Recycle bin. used to hide payloads            |

Path comparison is case-insensitive with backslashes normalized to forward slashes.

### 3.4 Hidden and Orphaned Process Detection

**MITRE ATT&CK: T1564.001 (Hide Artifacts: Hidden Files and Directories),
T1055 (Process Injection)**

An orphaned process is one whose parent PID no longer exists. While some orphans are normal
on Windows (csrss.exe, wininit.exe, winlogon.exe, services.exe, lsass.exe, fontdrvhost.exe,
smss.exe are expected to be orphaned because their parent smss.exe exits during boot), an
unexpected orphan. especially one with network connections. can indicate process
injection or a killed dropper that left behind a child implant.

Decision tree:

```
process P with parent PID X:

    if X exists:
        P is parented normally -> no finding
    else if X does not exist:
        if P.name in {csrss.exe, wininit.exe, winlogon.exe,
                      services.exe, lsass.exe, fontdrvhost.exe, smss.exe}:
            expected bootstrap orphan -> no finding
        else:
            unexpected orphan -> finding (MEDIUM)

    if P.status == ZOMBIE:
        zombie process -> finding (LOW)

    [Linux only] if /proc/{P.pid} does not exist but P is in process table:
        hidden from /proc -> finding (HIGH)
```

### 3.5 DLL Injection Indicators

**MITRE ATT&CK: T1055.001 (Process Injection: Dynamic-link Library Injection),
T1574.002 (Hijack Execution Flow: DLL Side-Loading)**

On Windows, the module inspects each process's memory-mapped files (via `memory_maps()`) and
flags DLLs loaded from outside expected directories:

Expected DLL directories:
- `%SYSTEMROOT%\System32`
- `%SYSTEMROOT%\SysWOW64`
- `%SYSTEMROOT%\WinSxS`
- The same directory as the process executable

A DLL loaded from outside these locations is checked against suspect path fragments:

- `/temp/`, `/tmp/`, `/appdata/local/temp`, `/dev/shm/`, `/users/default/`,
  `/windows/debug/`

If a DLL matches, it is flagged as a potential injection indicator. The finding includes the
full DLL path and which fragment triggered the match.

On Linux, the module reads `/proc/<pid>/maps` and flags any `.so` file loaded from `/tmp/`
or `/dev/shm/`, which are common staging areas for reflective .so injection.

Severity: **HIGH** for any DLL/SO loaded from a suspect path.

. -

## 4. Module: Persistence Hunt

### 4.1 Registry Run Key Enumeration

**MITRE ATT&CK: T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder)**

The module reads the following registry keys under both HKLM and HKCU:

- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`

Each value is evaluated:

1. Extract the executable path from the registry value (strip arguments, unquote)
2. Check if the executable exists on disk
3. Verify the Authenticode signature
4. Check against the known RAT name list
5. Check if the path is in a suspicious location

Findings are generated when:
- The target binary is unsigned: **MEDIUM**
- The target binary is in a temp or user-writable directory: **HIGH**
- The target binary name matches a known RAT: **CRITICAL**
- The target binary does not exist on disk: **LOW** (stale entry, may indicate cleanup)

### 4.2 Winlogon Shell and Userinit Hijacking

**MITRE ATT&CK: T1547.004 (Boot or Logon Autostart Execution: Winlogon Helper DLL)**

Registry key: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Values monitored:
- `Shell`. should be `explorer.exe` and nothing else
- `Userinit`. should be `userinit.exe,` (with trailing comma, no additional entries)

Any deviation from the expected default triggers a **CRITICAL** finding because Winlogon
hijacking gives an attacker code execution on every logon, running as the user's session.

### 4.3 Image File Execution Options (IFEO) Debugger Hijacking

**MITRE ATT&CK: T1546.012 (Event Triggered Execution: Image File Execution Options Injection)**

Registry key: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\`

The module enumerates all subkeys and checks for a `Debugger` value. This technique is
used by attackers to redirect execution of a target binary (like sethc.exe for sticky-keys
backdoors, or utilman.exe for accessibility backdoors) to an arbitrary executable.

Any IFEO entry with a Debugger value: **HIGH**
IFEO entry targeting an accessibility binary (sethc.exe, utilman.exe, osk.exe, narrator.exe,
magnify.exe): **CRITICAL**

### 4.4 AppInit_DLLs

**MITRE ATT&CK: T1546.010 (Event Triggered Execution: AppInit DLLs)**

Registry key: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`

Values monitored:
- `AppInit_DLLs`. should be empty
- `LoadAppInit_DLLs`. should be 0

If `LoadAppInit_DLLs` is set to 1 and `AppInit_DLLs` contains a path, every user-mode
process that loads user32.dll will also load the specified DLL. This is a well-known
injection vector.

Non-empty AppInit_DLLs with loading enabled: **CRITICAL**

### 4.5 Scheduled Task Enumeration

**MITRE ATT&CK: T1053.005 (Scheduled Task/Job: Scheduled Task)**

The module runs `schtasks /Query /FO CSV /V` and parses the output. Microsoft-authored
tasks (task author containing "Microsoft") are filtered out. Remaining tasks are evaluated:

- Task action pointing to an unsigned binary: **MEDIUM**
- Task action pointing to a binary in a temp directory: **HIGH**
- Task running as SYSTEM with a non-standard binary: **HIGH**
- Task with a hidden attribute enabled: **HIGH**
- Task created within the last 7 days with a suspicious binary path: **CRITICAL**

### 4.6 WMI Event Subscription Detection

**MITRE ATT&CK: T1546.003 (Event Triggered Execution: Windows Management Instrumentation
Event Subscription)**

WMI event subscriptions provide a fileless persistence mechanism. The module queries:

```
SELECT * FROM __EventFilter
SELECT * FROM __EventConsumer
SELECT * FROM __FilterToConsumerBinding
```

via `wmic` or PowerShell WMI cmdlets. Any active binding between an EventFilter and a
CommandLineEventConsumer or ActiveScriptEventConsumer is flagged:

- CommandLineEventConsumer running a script or unsigned binary: **HIGH**
- ActiveScriptEventConsumer (VBScript/JScript execution): **CRITICAL**

### 4.7 Startup Folder Contents

**MITRE ATT&CK: T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder)**

The module checks both the per-user and all-users startup folders:

- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
- `%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup`

Each file in these directories is evaluated for:
- Script files (.vbs, .js, .bat, .cmd, .ps1, .wsf): **HIGH**
- Executable files that are unsigned: **MEDIUM**
- Shortcut files (.lnk) pointing to unsigned or temp-directory binaries: **MEDIUM**

### 4.8 Service Binary Path Audit

**MITRE ATT&CK: T1543.003 (Create or Modify System Process: Windows Service),
T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking)**

The module enumerates all Windows services and checks the binary path:

1. Parse the `ImagePath` value (handle `svchost.exe -k` grouping, quoted paths)
2. Verify the target binary exists
3. Check Authenticode signature
4. Flag unquoted paths with spaces (unquoted service path vulnerability)
5. Flag binaries outside standard system directories

Findings:
- Unquoted service path with spaces: **MEDIUM** (privilege escalation vector)
- Service binary unsigned and outside Program Files: **HIGH**
- Service binary in a temp or user-writable directory: **CRITICAL**

. -

## 5. Module: Certificate Audit

### 5.1 Root CA Store Enumeration

**MITRE ATT&CK: T1553.004 (Subvert Trust Controls: Install Root Certificate),
T1557.001 (Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay)**

The module pulls certificates from both `LocalMachine\Root` and `CurrentUser\Root` stores
via PowerShell. For each certificate, it extracts:

- Thumbprint
- Subject and Issuer (RFC 4514 format)
- Validity period (NotBefore, NotAfter)
- Whether a private key is present
- Store location

The registry key last-write time is used as a proxy for when the certificate was added
to the store:

```
HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\{thumbprint}
HKCU\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\{thumbprint}
```

The `QueryInfoKey` call returns the last-write FILETIME (100-nanosecond intervals since
1601-01-01 UTC), which is converted to a UTC datetime.

### 5.2 Detection Rules

**Rule 1: TLS Interception Capable Certificate**

A root CA certificate is flagged as interception-capable when all three conditions are true:

- Self-signed (Subject == Issuer)
- Has Server Authentication Extended Key Usage (OID 1.3.6.1.5.5.7.3.1)
- Private key is present in the store

This combination means the certificate can sign arbitrary TLS certificates for any domain,
which is how TLS-intercepting proxies (corporate MITM, malware SSL-stripping) operate.

Severity: **CRITICAL**

**Rule 2: Unknown Certificate Authority**

The module maintains a list of 30 known major CAs:

Microsoft, DigiCert, GlobalSign, Comodo/Sectigo, Entrust, VeriSign, Thawte, GeoTrust,
GoDaddy, USERTrust, Baltimore, Starfield, Amazon Trust, IdenTrust, Let's Encrypt/ISRG,
Buypass, Certum, Actalis, QuoVadis, SECOM, AffirmTrust, Trustwave, SSL.com, Certigna,
T-Systems/TeleSec, SwissSign.

The Organization (O) and Common Name (CN) attributes of the certificate subject are checked
against this list. A root CA from an unrecognized organization is unusual and warrants
investigation.

Severity: **MEDIUM** (many enterprises install internal CAs, so this is expected in
corporate environments but still worth logging)

**Rule 3: Recently Added Certificate**

If the certificate was added to the store within the last 30 days (based on registry
key timestamp, falling back to the NotBefore date), it is flagged. Recent additions
to the root store outside of Windows Update cycles are suspicious.

Severity: **LOW** (informational, but valuable for timeline analysis during incident response)

**Rule 4: Excessive Validity Period**

Root CA certificates valid for more than 20 years are flagged. While some legitimate CAs
have long validity periods, attacker-installed root certificates often have absurdly long
validity (50+ years) to avoid expiration-related detection.

Severity: **LOW**

### 5.3 Certificate Store Tampering Context

Attackers install rogue root certificates for several purposes:

1. **TLS interception**. decrypt and inspect or modify HTTPS traffic
2. **Code signing**. sign malicious binaries with a trusted certificate
3. **Credential harvesting**. present convincing phishing pages with valid TLS
4. **Defense evasion**. bypass certificate-pinned applications

The certificate audit module focuses on detecting category 1 (interception) because it
requires the most specific conditions (self-signed + ServerAuth EKU + private key) and
represents the highest immediate risk.

. -

## 6. Module: ARP Anomaly Detection

### 6.1 ARP Table Parsing

**MITRE ATT&CK: T1557.002 (Adversary-in-the-Middle: ARP Cache Poisoning)**

The module runs `arp -a` and parses the output with regex to extract IP-to-MAC mappings.
MAC addresses are normalized to lowercase, zero-padded, colon-separated format
(e.g., `0a:1b:2c:3d:4e:5f`).

Noise filtering removes:
- Broadcast MACs: `ff:ff:ff:ff:ff:ff`
- Zero MACs: `00:00:00:00:00:00`
- IPv4 multicast prefix: `01:00:5e`
- IPv6 multicast prefix: `33:33`
- Multicast IP range: 224.0.0.0/4
- Subnet broadcast: addresses ending in `.255`

### 6.2 Duplicate MAC Detection

When multiple IP addresses resolve to the same MAC address, it may indicate ARP spoofing.
The module groups IPs by MAC and flags any MAC claimed by more than one IP.

Severity: **HIGH**. this is the primary indicator of an active ARP spoofing attack.

Caveat: Some legitimate scenarios produce duplicate MACs (router interfaces, HSRP/VRRP,
virtual machines sharing a bridge). Analysts should verify the flagged IPs against known
infrastructure.

### 6.3 Baseline Comparison

The module supports saving and loading a baseline snapshot of the ARP table as a JSON file.
On subsequent runs, the current ARP table is compared against the baseline:

- **MAC change for the gateway IP**: **HIGH** severity. A gateway MAC change is the primary
  indicator of ARP spoofing targeting the default route, which would allow an attacker to
  intercept all outbound traffic.
- **MAC change for any other IP**: **MEDIUM** severity (labeled as "WARN"). Could indicate
  a device swap, DHCP reassignment, or targeted ARP spoofing.

The `--update` flag overwrites the baseline with the current snapshot after checks complete,
allowing incremental monitoring over time. If no baseline exists on first run, the current
state is saved as the new baseline.

. -

## 7. Severity Model and Triage Priorities

### 7.1 Severity Rationale

The five-tier model is designed to be actionable without generating excessive noise:

**CRITICAL** findings represent conditions that should not exist on a clean system:
- Known RAT process name running
- Interception-capable rogue root certificate
- Winlogon Shell/Userinit hijacked
- AppInit_DLLs injection active
- Unsigned binary in temp directory connected to C2 port

**HIGH** findings represent strong indicators that need human investigation:
- C2 port connection from signed process
- Beaconing with CV under 10%
- Gateway MAC address change
- DLL loaded from suspect path
- IFEO debugger hijack

**MEDIUM** findings are anomalies that may be benign but should be logged:
- Beacon candidate with 10-15% CV
- Unsigned binary in non-standard path
- Unknown root CA in certificate store
- Orphaned non-bootstrap process
- Non-Microsoft scheduled task with unsigned action

**LOW** findings are informational data points:
- Recently added root certificate
- Excessive certificate validity
- Zombie process
- Stale registry Run entry (binary missing)

**INFO** findings are baseline telemetry:
- Total connection count
- Process scan statistics
- ARP table size

### 7.2 Alert Triage Order

When processing a scan report with multiple findings, triage in this order:

1. CRITICAL findings with network activity (active C2 communication)
2. CRITICAL findings without network activity (persistence, certificate tampering)
3. HIGH findings with network correlation (beacon + unsigned binary combo)
4. HIGH findings standalone
5. MEDIUM findings grouped by module

For each finding, the report includes the module name, severity, a title line, detailed
description, and UTC timestamp. The JSON output format allows direct ingestion into SIEM
platforms or custom dashboards.

. -

## 8. MITRE ATT&CK Mapping

The table below maps every detection rule to its primary ATT&CK technique, sub-technique
where applicable, tactic category, and which module performs the detection.

| Technique ID | Name | Tactic | Module | Detection Method |
|---|---|---|---|---|
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | Network Scan | Beacon interval analysis (CV <= 15%, >= 4 samples, avg >= 1.0s) |
| T1095 | Non-Application Layer Protocol | Command and Control | Network Scan | C2 port matching against known bad port list |
| T1571 | Non-Standard Port | Command and Control | Network Scan | Static port list: 4444, 5555, 6666, 1177, 3127, 9999, 31337 |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | Command and Control | Network Scan | Beacon regularity analysis (encrypted C2 still shows timing patterns) |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | Command and Control | Network Scan | Same as T1573.001. timing analysis is protocol-agnostic |
| T1036.001 | Masquerading: Invalid Code Signature | Defense Evasion | Process Integrity | WinVerifyTrust (embedded) + CryptCATAdmin (catalog) verification |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Defense Evasion | Process Integrity | Trusted-path allowlist check, binary signing verification |
| T1553.002 | Subvert Trust Controls: Code Signing | Defense Evasion | Process Integrity | Authenticode verification via WinVerifyTrust API |
| T1055 | Process Injection | Defense Evasion | Process Integrity | Orphaned process detection (parent PID no longer exists) |
| T1055.001 | DLL Injection | Defense Evasion | Process Integrity | Memory-mapped file audit for DLLs from suspect directories |
| T1574.002 | DLL Side-Loading | Persistence | Process Integrity | DLL path outside System32/SysWOW64/WinSxS/exe directory |
| T1564.001 | Hidden Files and Directories | Defense Evasion | Process Integrity | Process visible in table but missing from /proc (Linux) |
| T1204.002 | User Execution: Malicious File | Execution | Process Integrity | Executable in temp/staging directory with active connections |
| T1059.001 | PowerShell | Execution | Process Integrity | Process name matching against known attack tool list |
| T1059.003 | Windows Command Shell | Execution | Process Integrity | Process name matching against known attack tool list |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence | Persistence Hunt | Registry enumeration of Run/RunOnce + startup folder scan |
| T1547.004 | Winlogon Helper DLL | Persistence | Persistence Hunt | Winlogon Shell and Userinit value validation |
| T1546.003 | WMI Event Subscription | Persistence | Persistence Hunt | WMI EventFilter/Consumer/Binding query |
| T1546.010 | AppInit DLLs | Persistence | Persistence Hunt | Registry check for LoadAppInit_DLLs + AppInit_DLLs values |
| T1546.012 | Image File Execution Options Injection | Persistence | Persistence Hunt | IFEO subkey enumeration for Debugger values |
| T1053.005 | Scheduled Task | Execution | Persistence Hunt | schtasks CSV output parsing, non-Microsoft task filtering |
| T1543.003 | Windows Service | Persistence | Persistence Hunt | Service ImagePath audit, unquoted path detection |
| T1574.001 | DLL Search Order Hijacking | Persistence | Persistence Hunt | Service binary path analysis for unquoted spaces |
| T1553.004 | Install Root Certificate | Defense Evasion | Certificate Audit | Root store enumeration, unknown CA matching, recency check |
| T1557.001 | LLMNR/NBT-NS Poisoning and SMB Relay | Credential Access | Certificate Audit | Interception-capable cert detection (self-signed + ServerAuth + PK) |
| T1557.002 | ARP Cache Poisoning | Credential Access | ARP Anomaly | Duplicate MAC detection, baseline MAC comparison |

. -

## 9. Red Team Evasion Techniques and Defensive Countermeasures

This section describes known evasion techniques that red team operators use against
host-based detection tools, and how Sentinel's detection logic accounts for them.

### 9.1 Jitter Tuning

**Attack**: Red team operators configure their C2 implants with high jitter (30-50%) to
break the statistical regularity of beacon intervals.

**Countermeasure**: The 15% CV threshold is deliberately set below the typical red team
jitter range. Operators who set jitter above 15% will evade the current beacon detection.
However, the connection itself is still subject to C2 port matching, process trust
verification, and signature checking. A high-jitter beacon from an unsigned binary in a
temp directory still produces CRITICAL findings through those other checks.

**Tuning**: To catch higher-jitter beacons, increase the observation duration and sample
count requirements rather than raising the CV threshold. A 5-minute observation window
with MIN_BEACON_SAMPLES=8 catches 20-25% jitter beacons with acceptable false positive
rates.

### 9.2 Reflective DLL Injection and In-Memory Execution

**Attack**: Red team operators load implant DLLs directly into memory without writing
to disk, bypassing filesystem-based detection.

**Countermeasure**: The DLL injection check inspects `memory_maps()` output, which
includes memory-mapped regions regardless of whether the DLL was loaded from disk or
injected reflectively. However, truly reflective injection that avoids the standard
`LoadLibrary` path may not appear in memory maps. In that case, the orphaned process
detection and network connection analysis provide fallback detection. the implant
still needs to open sockets.

### 9.3 Process Name Masquerading

**Attack**: Renaming a RAT binary to mimic a legitimate process (e.g., "svchost.exe"
running from `%PUBLIC%\`).

**Countermeasure**: The process integrity module checks both the process name AND the
executable path. A legitimate svchost.exe runs from `%SYSTEMROOT%\System32\` and is
catalog-signed. A masquerading copy in a non-standard directory will fail the trusted
path check and signature verification, generating findings even if the name looks normal.

### 9.4 LOLBins (Living Off the Land Binaries)

**Attack**: Using signed, trusted OS binaries (mshta.exe, rundll32.exe, regsvr32.exe,
certutil.exe) to execute malicious payloads, bypassing signature-based detection.

**Countermeasure**: LOLBin abuse is partially addressed by the persistence module, which
checks what binaries scheduled tasks and services point to. The network module flags any
outbound connection regardless of binary trust, so a LOLBin downloading a payload from
a C2 port will still trigger a finding. Full LOLBin detection requires command-line
argument logging (Sysmon Event ID 1, or ETW tracing), which is outside the current scope
of Sentinel but can be integrated as a future module.

### 9.5 Domain Fronting and CDN Abuse

**Attack**: Routing C2 traffic through legitimate CDN domains (Azure, CloudFront, Fastly)
so that DNS and SNI analysis shows benign destinations.

**Countermeasure**: Beacon detection is transport-agnostic. it measures timing regularity,
not destination reputation. A domain-fronted C2 channel with consistent beacon intervals
will still be caught by the CV analysis. The ASN resolution step will show the CDN provider,
which an analyst can correlate with the beaconing flag.

### 9.6 Direct Syscalls and NTAPI Usage

**Attack**: Bypassing user-mode hooks (ETW, AMSI) by invoking syscall stubs directly
instead of going through ntdll.dll.

**Countermeasure**: Sentinel does not rely on API hooking. The process integrity module
reads the process table and memory maps directly via OS interfaces (psutil wrapping procfs
on Linux, or NtQuerySystemInformation on Windows). The network module reads the TCP table
directly. Neither can be bypassed by direct syscall techniques alone.

### 9.7 Timestomping

**Attack**: Modifying file creation and modification timestamps to blend a malicious
binary into its surroundings.

**Countermeasure**: The certificate audit module uses registry key last-write timestamps
rather than file timestamps to detect recently added certificates, making it resistant
to timestomping. For the persistence module, the detection is based on binary properties
(signature, path, name) rather than timestamps.

. -

## 10. Operational Procedures

### 10.1 Deployment Modes

**Quick scan** (default): Skips beaconing analysis and deep DLL inspection. Runs in under
30 seconds on most systems. Suitable for periodic automated checks.

**Full scan**: Enables all detection logic including the 60-second beacon observation
window. Runs in 1-2 minutes. Suitable for incident response or scheduled deep scans.

### 10.2 Module Selection

Individual modules can be run in isolation:

```
sentinel-scan --modules net_scan proc_integrity
sentinel-scan --modules persistence
sentinel-scan --modules cert_audit arp_anomaly
```

Module names for selection: `net_scan`, `proc_integrity`, `persistence`, `cert_audit`,
`arp_anomaly`.

### 10.3 Output Formats

**Text mode** (default): Human-readable report with severity-sorted findings. Useful for
interactive triage and terminal-based workflows.

**JSON mode** (`--json` flag or `.json` output file extension): Machine-readable output
with structured metadata (hostname, OS, architecture, Python version, scan start/end times),
summary statistics (total count, count by severity), and an array of finding objects.

### 10.4 False Positive Tuning

Common false positive sources and recommended handling:

| False positive | Cause | Fix |
|---|---|---|
| Unsigned binary alert for internal tools | Custom enterprise software | Add to a local allowlist file |
| Unknown CA in root store | Enterprise PKI or VPN provider | Verify the CA thumbprint and add to known_cas list |
| Scheduled task flagged as suspicious | Third-party software installer | Verify publisher and add task path to exclusions |
| ARP duplicate MAC | Virtual machines or VRRP | Document expected duplicate MACs in baseline |
| Beacon detection hit on NTP or update service | Regular polling pattern | Exclude known-good destinations by IP or port |

### 10.5 Integration with Threat Hunting Workflows

Sentinel output can be fed into a broader threat hunting pipeline:

1. Run Sentinel on all endpoints in a fleet (via management tool push)
2. Collect JSON reports centrally
3. Aggregate findings by severity and module
4. Cross-reference CRITICAL/HIGH findings with network flow logs
5. Correlate beacon candidates with DNS query logs for domain resolution
6. Feed confirmed IOCs back into network-level blocklists

### 10.6 Purple Team Exercise Support

During purple team exercises, Sentinel serves both sides:

**Red team usage**: Run Sentinel against your own implant before engagement to verify
whether your C2 configuration, beacon interval, and process injection technique are
detectable. Tune your tradecraft until Sentinel produces no findings, then log the
configuration for your engagement report.

**Blue team usage**: Run Sentinel continuously during the exercise. Compare findings
against the red team's activity log post-exercise to measure detection coverage. Any
red team action that produced no finding represents a gap to address.

. -

## 11. Detection Gaps and Future Work

The following attack techniques are not currently detected by Sentinel and represent
planned future modules:

| Gap | Technique | Planned approach |
|---|---|---|
| ETW tampering | T1562.006 | Monitor ETW provider registration and patch detection |
| AMSI bypass | T1562.001 | Check amsi.dll integrity in running processes |
| Credential dumping (LSASS) | T1003.001 | Monitor LSASS handle access patterns |
| SAM database access | T1003.002 | Audit file access to SAM/SECURITY hives |
| Kerberoasting | T1558.003 | Monitor for bulk TGS requests |
| DNS tunneling | T1071.004 | Entropy analysis on DNS query payloads |
| COM object hijacking | T1546.015 | Registry audit of InprocServer32 overrides |
| DGA domain detection | T1568.002 | Character frequency and bigram entropy scoring |
| Log clearing | T1070.001 | Windows Event Log channel monitoring |
| SSP injection | T1547.005 | LSA Security Packages registry monitoring |

. -

## 12. References

- MITRE ATT&CK Framework v14: https://attack.mitre.org/
- MITRE ATT&CK Technique index: https://attack.mitre.org/techniques/enterprise/
- Microsoft WinVerifyTrust documentation: https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust
- Microsoft CryptCATAdmin API: https://learn.microsoft.com/en-us/windows/win32/api/mscat/
- psutil documentation: https://psutil.readthedocs.io/
- cryptography library x509 module: https://cryptography.io/en/latest/x509/