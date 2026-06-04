"""ARP anomaly detection -- enumerate the ARP table and flag spoofing indicators."""
# All Rights Reserved. Proprietary, no forking, no redistribution.

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

BASELINE_FILE = Path("arp_baseline.json")

IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
MAC_RE = re.compile(r"((?:[0-9a-fA-F]{1,2}[:\-]){5}[0-9a-fA-F]{1,2})")


def normalize_mac(raw: str) -> str:
    """Lowercase, zero-pad each octet, colon-separated."""
    parts = re.split(r"[:\-]", raw)
    return ":".join(p.zfill(2).lower() for p in parts)


def is_noise(ip: str, mac: str) -> bool:
    """Filter broadcast, multicast, and incomplete entries."""
    if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return True
    if mac.startswith("01:00:5e") or mac.startswith("33:33"):
        return True
    return int(ip.split(".")[0]) >= 224 or ip.endswith(".255")


def read_arp_table() -> dict[str, str]:
    """Run arp -a and parse into {ip: mac} mapping."""
    try:
        out = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print("[!] arp command not found -- install net-tools or iproute2", file=sys.stderr)
        sys.exit(1)

    table: dict[str, str] = {}
    for line in out.splitlines():
        ip_match = IP_RE.search(line)
        mac_match = MAC_RE.search(line)
        if not ip_match or not mac_match:
            continue
        ip = ip_match.group(1)
        mac = normalize_mac(mac_match.group(1))
        if is_noise(ip, mac):
            continue
        table[ip] = mac
    return table


def detect_shared_macs(table: dict[str, str]) -> list[dict]:
    """Find MACs claimed by multiple IPs -- ARP spoofing indicator."""
    mac_to_ips: dict[str, list[str]] = defaultdict(list)
    for ip, mac in table.items():
        mac_to_ips[mac].append(ip)
    return [
        {"type": "shared_mac", "mac": mac, "ips": sorted(ips),
         "detail": f"MAC {mac} claimed by {len(ips)} IPs: {', '.join(sorted(ips))}"}
        for mac, ips in mac_to_ips.items() if len(ips) > 1
    ]


def detect_baseline_changes(table: dict[str, str], baseline: dict[str, str],
                            gateway_ip: str | None = None) -> list[dict]:
    """Compare current snapshot against saved baseline for MAC flips."""
    alerts = []
    for ip, mac in table.items():
        old = baseline.get(ip)
        if old and old != mac:
            sev = "HIGH" if ip == gateway_ip else "WARN"
            kind = "gateway_mac_change" if ip == gateway_ip else "mac_changed"
            alerts.append({"type": kind, "severity": sev, "ip": ip,
                           "old_mac": old, "new_mac": mac,
                           "detail": f"[{sev}] {ip} MAC flipped: {old} -> {mac}"})
    return alerts


def load_baseline(path: Path) -> dict:
    """Load baseline JSON. Returns empty dict if missing."""
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)


def save_baseline(path: Path, table: dict[str, str], gateway: str | None = None) -> None:
    data = {"gateway": gateway, "entries": table}
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Baseline saved to {path} ({len(table)} entries)")


def run(baseline_path: Path, update: bool = False, gateway: str | None = None) -> list[dict]:
    table = read_arp_table()
    print(f"[*] ARP table: {len(table)} unicast entries")

    alerts = detect_shared_macs(table)

    baseline_data = load_baseline(baseline_path)
    if baseline_data:
        saved_gw = gateway or baseline_data.get("gateway")
        entries = baseline_data.get("entries", {})
        alerts += detect_baseline_changes(table, entries, saved_gw)
        print(f"[*] Compared against baseline ({len(entries)} saved entries)")
    else:
        print("[*] No baseline found -- saving current state as baseline")
        save_baseline(baseline_path, table, gateway)

    if update and baseline_data:
        save_baseline(baseline_path, table, gateway)

    if alerts:
        print(f"\n[!] {len(alerts)} alert(s):")
        for a in alerts:
            print(f"  - {a['detail']}")
    else:
        print("\n[+] No anomalies detected")

    return alerts


def main() -> None:
    parser = argparse.ArgumentParser(description="ARP anomaly detection")
    parser.add_argument("--baseline", type=Path, default=BASELINE_FILE,
                        help="path to baseline JSON file")
    parser.add_argument("--update", action="store_true",
                        help="overwrite baseline with current snapshot after checks")
    parser.add_argument("--gateway", type=str, default=None,
                        help="gateway IP to flag with high severity on MAC change")
    args = parser.parse_args()
    run(args.baseline, args.update, args.gateway)


if __name__ == "__main__":
    main()
