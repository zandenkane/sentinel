"""Main orchestrator .  runs all detection modules and produces a consolidated report."""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sentinel.modules import (
    arp_anomaly,
    cert_audit,
    net_scan,
    persistence,
    proc_integrity,
)


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    module: str
    severity: Severity
    title: str
    detail: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def as_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "timestamp": self.timestamp,
        }


# Each module exposes run(quick: bool) -> list[Finding].
MODULES = [
    ("Network Scan", net_scan),
    ("Process Integrity", proc_integrity),
    ("Persistence Hunt", persistence),
    ("Certificate Audit", cert_audit),
    ("ARP Anomaly Detection", arp_anomaly),
]

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _header() -> dict[str, str]:
    return {
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "python": platform.python_version(),
        "scan_start": datetime.now(timezone.utc).isoformat(),
    }


def run_modules(quick: bool, selected: list[str] | None = None) -> list[Finding]:
    """Run detection modules and collect findings."""
    results: list[Finding] = []

    for label, mod in MODULES:
        mod_key = mod.__name__.rsplit(".", 1)[-1]
        if selected and mod_key not in selected:
            continue

        tag = "quick" if quick else "full"
        print(f"[*] Running {label} ({tag})...")
        t0 = time.monotonic()

        try:
            findings = mod.run(quick=quick)
            elapsed = time.monotonic() - t0
            print(f"    done in {elapsed:.1f}s .  {len(findings)} finding(s)")
            results.extend(findings)
        except Exception as exc:
            elapsed = time.monotonic() - t0
            print(f"    FAILED after {elapsed:.1f}s: {exc}")
            results.append(Finding(
                module=mod_key,
                severity=Severity.MEDIUM,
                title=f"{label} module error",
                detail=str(exc),
            ))

    return results


def build_report(findings: list[Finding], header: dict[str, str]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    return {
        "meta": header,
        "scan_end": datetime.now(timezone.utc).isoformat(),
        "summary": {"total": len(findings), "by_severity": counts},
        "findings": [f.as_dict() for f in findings],
    }


def format_text_report(report: dict[str, Any]) -> str:
    meta = report["meta"]
    summary = report["summary"]
    lines = [
        "", "=" * 60, "  SENTINEL SCAN REPORT", "=" * 60,
        f"  Host:     {meta['hostname']}",
        f"  OS:       {meta['os']}",
        f"  Arch:     {meta['arch']}",
        f"  Python:   {meta['python']}",
        f"  Started:  {meta['scan_start']}",
        f"  Finished: {report['scan_end']}",
        "-" * 60,
        f"  Total findings: {summary['total']}",
    ]
    for sev, count in summary.get("by_severity", {}).items():
        lines.append(f"    {sev.upper():>10}: {count}")
    lines.append("-" * 60)

    if not report["findings"]:
        lines += ["  No findings .  system looks clean.", "=" * 60]
        return "\n".join(lines)

    sorted_f = sorted(report["findings"], key=lambda f: SEV_ORDER.get(f["severity"], 99))
    for i, f in enumerate(sorted_f, 1):
        lines.append(f"\n  [{i}] [{f['severity'].upper()}] {f['title']}")
        lines.append(f"      Module: {f['module']}")
        lines.append(f"      Detail: {f['detail']}")

    lines += ["", "=" * 60]
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="sentinel-scan",
        description="Host-based threat detection scanner",
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--quick", action="store_true", default=True,
                      help="Fast scan .  skip slow checks (default)")
    mode.add_argument("--full", action="store_true",
                      help="Deep scan .  run all checks")
    p.add_argument("--json", action="store_true", dest="json_out",
                   help="Output as JSON instead of text")
    p.add_argument("-o", "--output", type=str, default=None,
                   help="Write report to file")
    p.add_argument("-m", "--modules", nargs="+", default=None,
                   choices=["net_scan", "proc_integrity", "persistence",
                            "cert_audit", "arp_anomaly"],
                   help="Run only specific modules")
    p.add_argument("--list-modules", action="store_true",
                   help="List available modules and exit")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.list_modules:
        print("Available modules:")
        for label, mod in MODULES:
            key = mod.__name__.rsplit(".", 1)[-1]
            print(f"  {key:20s}  {label}")
        return 0

    quick = not args.full
    header = _header()
    print(f"[*] Sentinel scanner starting on {header['hostname']}")
    print(f"[*] Mode: {'quick' if quick else 'full'}\n")

    findings = run_modules(quick=quick, selected=args.modules)
    report = build_report(findings, header)

    use_json = args.json_out or (args.output and args.output.endswith(".json"))
    output_text = json.dumps(report, indent=2) if use_json else format_text_report(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output_text)
        print(f"[*] Report written to {args.output}")
    else:
        print(output_text)

    high_or_crit = sum(
        1 for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)
    )
    return 1 if high_or_crit else 0


if __name__ == "__main__":
    sys.exit(main())
