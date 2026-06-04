File written to C:\Users\zerox\Dev\sentinel\docs\methodology.md (625 lines).

Covers all requested topics:

1. Network-based IOCs:
   - C2 beaconing detection (coefficient of variation, byte-size consistency, JA3/JA3S fingerprinting, HTTP header anomalies, frequency-domain DFT analysis)
   - Known bad ports and protocol-port mismatch detection
   - DNS indicators (query length, volume spikes, TXT abuse, DGA entropy scoring, newly registered domains)
   - Lateral movement patterns (SMB/RPC scanning, WMI/WinRM, Pass-the-Hash/Ticket, Kerberoasting)

2. Host-based IOCs:
   - Process integrity and signing verification (unsigned binaries, signature failures, process-image mismatch, process hollowing, phantom DLL loading)
   - Persistence mechanisms (registry Run keys, scheduled tasks, services, WMI event subscriptions, startup folder, COM hijacking, DLL search order hijacking)
   - Certificate store tampering (root CA additions, certificate removal, SIP/Trust Provider modification)
   - Credential access (LSASS monitoring, SAM/NTDS access, credential file harvesting)
   - Defense evasion detection (ETW tampering, AMSI bypass, security tool termination, log clearing, timestomping)
   - Command execution monitoring (PowerShell, cmd.exe, WSH, mshta.exe)

3. Red team and blue team usage:
   - Red team evasion techniques (jitter tuning, domain fronting, reflective DLL injection, direct syscalls, process ghosting, LOLBins, SSP injection, DPAPI abuse)
   - Blue team workflows (alert triage, threat hunting integration, detection tuning feedback loops, purple team exercises)

4. MITRE ATT&CK techniques referenced: T1003.001, T1003.002, T1003.003, T1021.002, T1021.006, T1027, T1036.005, T1047, T1048, T1048.003, T1053.005, T1055, T1055.012, T1059.001, T1059.003, T1059.005, T1070.001, T1070.006, T1071.001, T1071.004, T1090, T1090.001, T1090.002, T1090.004, T1095, T1197, T1218.005, T1218.011, T1547.001, T1547.005, T1547.006, T1543.002, T1543.003, T1546.003, T1546.004, T1546.015, T1550.002, T1550.003, T1552.001, T1553.003, T1553.004, T1555.003, T1555.004, T1557.001, T1558.003, T1562.001, T1562.006, T1566.001, T1568.002, T1568.003, T1572, T1573.001, T1573.002, T1574.001, T1574.002, T1574.006, T1620, T1098.004, T1053.003