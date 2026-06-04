File written: C:\Users\zerox\sentinel\persistence.py (286 lines)

Verified working on Windows -- all 8 check categories execute and produce real findings:
- Run/RunOnce keys: 11 findings
- Winlogon Shell/Userinit: 0 (clean)
- IFEO debugger hijacks: 0 (clean)
- AppInit_DLLs: 0 (clean)
- Scheduled tasks (non-Microsoft): 304 findings
- WMI event subscriptions: 1 finding
- Startup folder: 0 (clean)
- Services with unusual paths: 4 findings

Usage:
  python sentinel/persistence.py -v          # verbose text output
  python sentinel/persistence.py -f json     # JSON output
  
API:
  from sentinel.persistence import scan, report
  findings = scan(verbose=True)
  print(report(findings, fmt="json"))