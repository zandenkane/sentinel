"""Host-based threat detection and endpoint security framework."""

__version__ = "0.2.0"

from sentinel.finding import Finding, Severity, SEVERITY_RANK

__all__ = [
    "__version__",
    "Finding",
    "Severity",
    "SEVERITY_RANK",
    "arp",
    "certs",
    "network",
    "persistence",
    "process",
    "scanner",
]
