# Changelog

All notable changes to sentinel are documented in this file.

## [0.2.0] - 2026-05-29

### Added

- Memory forensics module: RWX region detection, shellcode signature matching, process hollowing checks.
- Credential store theft detection for Chrome, Firefox, Edge, Brave, and Opera.
- DNS monitoring with DGA detection, tunneling analysis, and DoH bypass identification.
- Named pipe C2 detection with signatures for Cobalt Strike, Sliver, and Havoc.
- LSASS access detection: handle enumeration, PPL status checks, dump artifact scanning.
- `config.py` with yaml-based configuration loaded from `sentinel.yaml`.
- `finding.py` shared dataclass for structured scan results.
- `pyproject.toml` for pip-installable packaging.

### Changed

- Switched license to MIT.

### Fixed

- Command injection vulnerability in `network.py`.
- False negatives in `is_signed` checks on Linux.
- Certificate EKU bypass that allowed invalid extended key usage to pass validation.

## [0.1.0] - 2026-04-01

### Added

- Process integrity scanning with Authenticode signature verification.
- Network connection analysis with C2 port detection.
- Beaconing detection with jitter analysis.
- Persistence mechanism hunting across 12 check categories.
- Certificate store auditing.
- ARP anomaly detection.
