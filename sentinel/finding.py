"""Shared Finding dataclass used across all sentinel detection modules."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

logger = logging.getLogger(__name__)

Severity = Literal["critical", "high", "medium", "low", "info"]

SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


@dataclass
class Finding:
    """Single detection finding produced by any sentinel module.

    Every detection function across the project should return
    list[Finding] so callers get a uniform interface.
    """

    module: str
    title: str
    severity: Severity
    detail: str
    evidence: str
    mitre_id: str = ""
    path: str = ""
    pid: int = 0

    def __post_init__(self) -> None:
        valid: set[str] = {"critical", "high", "medium", "low", "info"}
        if self.severity not in valid:
            logger.warning("invalid severity %r, falling back to info", self.severity)
            self.severity = "info"

    # .  serialization helpers . 

    def to_dict(self) -> dict[str, Any]:
        """Return a plain dict suitable for JSON serialization."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Serialize to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    # .  display helpers . 

    def format_finding(self) -> str:
        """Produce a clean, human-readable text block."""
        sev_tag = self.severity.upper()
        lines = [
            f"[{sev_tag}] {self.title}",
            f"  Module   : {self.module}",
            f"  Detail   : {self.detail}",
            f"  Evidence : {self.evidence}",
        ]
        if self.mitre_id:
            lines.append(f"  MITRE    : {self.mitre_id}")
        if self.path:
            lines.append(f"  Path     : {self.path}")
        if self.pid:
            lines.append(f"  PID      : {self.pid}")
        return "\n".join(lines)
