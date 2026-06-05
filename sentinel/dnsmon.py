"""DNS query monitoring .  parse Windows DNS cache, flag DGA domains,
DNS tunneling indicators, DoH bypass attempts, and recently registered domains.

"""
from __future__ import annotations

import json
import logging
import math
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)

DGA_ENTROPY_THRESHOLD = 3.5
TUNNEL_LABEL_LEN = 40
YOUNG_DOMAIN_DAYS = 30
RDAP_BASE = "https://rdap.org/domain/"

DOH_PROVIDERS: dict[str, str] = {
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare",
    "8.8.8.8": "Google", "8.8.4.4": "Google",
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
}

_RECORD_NAME_RE = re.compile(r"Record Name\s*[.:]+\s*(.+)", re.IGNORECASE)
_DATA_RE = re.compile(
    r"(?:A \(Host\)|AAAA|CNAME).*?(?:Record|Data)\s*[.:]+\s*(.+)", re.IGNORECASE,
)


@dataclass
class Finding:
    domain: str
    kind: str          # dga | tunnel | doh_bypass | young_domain
    detail: str
    severity: str = "WARN"
    extra: dict = field(default_factory=dict)


@dataclass
class DnsReport:
    findings: list[Finding] = field(default_factory=list)
    cache_entries: int = 0
    errors: int = 0

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    @property
    def clean(self) -> bool:
        return len(self.findings) == 0


# .  entropy . . . . -

def shannon_entropy(label: str) -> float:
    """Shannon entropy in bits per character. English words ~2.5-3.0; random >3.5."""
    if not label:
        return 0.0
    n = len(label)
    freq: dict[str, int] = {}
    for ch in label:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# .  domain age via RDAP . . . . -

def domain_age_days(domain: str, timeout: float = 4.0) -> Optional[int]:
    """Query RDAP for registration date; return age in days or None on failure."""
    parts = domain.rstrip(".").split(".")
    if len(parts) < 2:
        return None
    registrable = ".".join(parts[-2:])
    req = urllib.request.Request(
        f"{RDAP_BASE}{registrable}", headers={"Accept": "application/rdap+json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError) as exc:
        log.debug("RDAP lookup failed for %s: %s", registrable, exc)
        return None
    for event in data.get("events", []):
        if event.get("eventAction") == "registration":
            try:
                dt = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                return (datetime.now(timezone.utc) - dt).days
            except (ValueError, TypeError, KeyError):
                pass
    return None


# .  DNS cache parsing (Windows) . . . -

def _parse_ipconfig_dns(text: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    current_name: Optional[str] = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("-"):
            continue
        m = _RECORD_NAME_RE.match(line)
        if m:
            current_name = m.group(1).strip().rstrip(".")
            continue
        m = _DATA_RE.match(line)
        if m and current_name:
            entries.append({"name": current_name, "data": m.group(1).strip()})
    return entries


def _parse_ps_dns(text: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    try:
        rows = json.loads(text)
        if not isinstance(rows, list):
            rows = [rows]
        for row in rows:
            name = row.get("Entry", "") or row.get("Name", "")
            data = str(row.get("Data", "") or row.get("RecordData", ""))
            if name:
                entries.append({"name": name.rstrip("."), "data": data})
    except (json.JSONDecodeError, TypeError):
        log.debug("Failed to parse PowerShell DNS JSON")
    return entries


def read_dns_cache() -> list[dict[str, str]]:
    """Read DNS client cache. Tries Get-DnsClientCache, falls back to ipconfig."""
    if sys.platform != "win32":
        log.warning("DNS cache reading is only supported on Windows")
        return []
    # PowerShell path
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-DnsClientCache | ConvertTo-Json -Compress"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0 and r.stdout.strip():
            parsed = _parse_ps_dns(r.stdout)
            if parsed:
                return parsed
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    # ipconfig fallback
    try:
        r = subprocess.run(
            ["ipconfig", "/displaydns"], capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            return _parse_ipconfig_dns(r.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return []


# .  helpers . . . . 

def _extract_sld(domain: str) -> str:
    parts = domain.rstrip(".").split(".")
    return parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")


def _longest_sub_label(domain: str) -> tuple[str, int]:
    parts = domain.rstrip(".").split(".")
    if len(parts) <= 2:
        return ("", 0)
    longest = max(parts[:-2], key=len)
    return (longest, len(longest))


# .  detectors . . . . -

def detect_dga(entries: list[dict[str, str]]) -> list[Finding]:
    """Flag domains whose SLD has Shannon entropy above threshold."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for e in entries:
        sld = _extract_sld(e["name"].lower())
        if not sld or sld in seen:
            continue
        seen.add(sld)
        h = shannon_entropy(sld)
        if h > DGA_ENTROPY_THRESHOLD:
            findings.append(Finding(
                domain=e["name"].lower(), kind="dga",
                detail=f"high entropy SLD '{sld}' (H={h:.2f}, threshold={DGA_ENTROPY_THRESHOLD})",
                severity="HIGH", extra={"sld": sld, "entropy": round(h, 4)},
            ))
    return findings


def detect_tunnel(entries: list[dict[str, str]]) -> list[Finding]:
    """Flag domains with subdomain labels longer than TUNNEL_LABEL_LEN."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for e in entries:
        domain = e["name"].lower()
        if domain in seen:
            continue
        seen.add(domain)
        label, length = _longest_sub_label(domain)
        if length > TUNNEL_LABEL_LEN:
            findings.append(Finding(
                domain=domain, kind="tunnel",
                detail=f"subdomain label '{label[:50]}' is {length} chars (threshold={TUNNEL_LABEL_LEN})",
                severity="HIGH", extra={"label": label, "length": length},
            ))
    return findings


def detect_doh_bypass(entries: list[dict[str, str]]) -> list[Finding]:
    """Flag cache entries resolving to known DoH provider IPs."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for e in entries:
        ip = e.get("data", "").strip()
        if ip not in DOH_PROVIDERS:
            continue
        domain = e["name"].lower()
        key = f"{domain}:{ip}"
        if key in seen:
            continue
        seen.add(key)
        provider = DOH_PROVIDERS[ip]
        findings.append(Finding(
            domain=domain, kind="doh_bypass",
            detail=f"resolves to {ip} ({provider} DoH) .  possible DNS bypass",
            severity="WARN", extra={"resolved_ip": ip, "provider": provider},
        ))
    return findings


def detect_young_domains(entries: list[dict[str, str]], max_lookups: int = 20) -> list[Finding]:
    """Check queried domains for recent registration via RDAP."""
    findings: list[Finding] = []
    checked: set[str] = set()
    count = 0
    for e in entries:
        if count >= max_lookups:
            break
        sld_tld = ".".join(e["name"].lower().rstrip(".").split(".")[-2:])
        if not sld_tld or sld_tld in checked:
            continue
        checked.add(sld_tld)
        count += 1
        age = domain_age_days(sld_tld)
        if age is not None and age <= YOUNG_DOMAIN_DAYS:
            findings.append(Finding(
                domain=e["name"].lower(), kind="young_domain",
                detail=f"'{sld_tld}' registered {age}d ago (threshold={YOUNG_DOMAIN_DAYS}d)",
                severity="WARN", extra={"registrable_domain": sld_tld, "age_days": age},
            ))
    return findings


# .  scan entry point . . . . -

def scan_dns_cache(
    check_dga: bool = True, check_tunnel: bool = True,
    check_doh: bool = True, check_age: bool = False,
    age_max_lookups: int = 20,
) -> DnsReport:
    report = DnsReport()
    entries = read_dns_cache()
    report.cache_entries = len(entries)
    if not entries:
        log.info("DNS cache is empty or unreadable")
        return report
    if check_dga:
        report.findings.extend(detect_dga(entries))
    if check_tunnel:
        report.findings.extend(detect_tunnel(entries))
    if check_doh:
        report.findings.extend(detect_doh_bypass(entries))
    if check_age:
        report.findings.extend(detect_young_domains(entries, max_lookups=age_max_lookups))
    return report


def print_report(report: DnsReport) -> None:
    print(f"\n{'=' * 60}")
    print(f"  DNS Cache Monitor  ({report.cache_entries} cached entries)")
    print("=" * 60)
    if report.clean:
        print("\n  [+] No suspicious DNS activity detected\n")
        return
    labels = {"dga": "Possible DGA domains", "tunnel": "DNS tunneling indicators",
              "doh_bypass": "DoH bypass indicators", "young_domain": "Recently registered"}
    by_kind: dict[str, list[Finding]] = {}
    for f in report.findings:
        by_kind.setdefault(f.kind, []).append(f)
    for kind, items in by_kind.items():
        print(f"\n[!] {labels.get(kind, kind)} ({len(items)}):")
        for f in items:
            print(f"  [{f.severity}] {f.domain}")
            print(f"         {f.detail}")
    print()


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description="DNS cache monitor")
    ap.add_argument("--age", action="store_true", help="Enable RDAP age checks")
    ap.add_argument("--age-limit", type=int, default=20, help="Max RDAP lookups")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING)
    report = scan_dns_cache(check_age=args.age, age_max_lookups=args.age_limit)
    print_report(report)
    sys.exit(0 if report.clean else 1)


if __name__ == "__main__":
    main()
