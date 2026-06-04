# All Rights Reserved. Proprietary and confidential.
# No forking, no redistribution.

"""Network connection analysis .  enumerates TCP connections, flags C2 ports,
detects beaconing patterns, checks process trust, and resolves ASN info."""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import psutil

C2_PORTS = {
    4444,   # Metasploit default
    5555,   # Android debug / various RATs
    6666,   # IRC-based botnets
    1177,   # DarkComet
    3127,   # MyDoom
    9999,   # various C2
    31337,  # Back Orifice / eleet
}

MIN_BEACON_SAMPLES = 4
BEACON_JITTER_THRESHOLD = 0.15

# Paths where legitimate binaries live on Windows
WIN_TRUSTED_DIRS = (
    "\\windows\\", "\\program files\\", "\\program files (x86)\\",
    "\\programdata\\microsoft\\", "\\windowsapps\\",
)


@dataclass
class ConnectionRecord:
    pid: int
    process_name: str
    exe_path: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    status: str
    is_c2_port: bool = False
    is_suspicious_process: bool = False
    asn_info: str = ""


@dataclass
class BeaconCandidate:
    remote_addr: str
    remote_port: int
    pid: int
    process_name: str
    interval_sec: float
    jitter_pct: float
    sample_count: int


@dataclass
class AnalysisResult:
    connections: list[ConnectionRecord] = field(default_factory=list)
    c2_flagged: list[ConnectionRecord] = field(default_factory=list)
    suspicious_procs: list[ConnectionRecord] = field(default_factory=list)
    beacon_candidates: list[BeaconCandidate] = field(default_factory=list)
    scan_time: float = 0.0


def _is_trusted_path(exe_path: str) -> bool:
    """Check if the executable lives in a known system/program directory."""
    lower = exe_path.lower()
    if sys.platform == "win32":
        return any(d in lower for d in WIN_TRUSTED_DIRS)
    return lower.startswith(("/usr/bin", "/usr/sbin", "/usr/lib", "/bin", "/sbin"))


def _check_signature_win(exe_path: str) -> bool:
    """Use PowerShell Get-AuthenticodeSignature to check if a PE is signed."""
    try:
        cmd = (
            f'(Get-AuthenticodeSignature '{exe_path}').Status -eq 'Valid''
        )
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, timeout=5,
        )
        return out.stdout.strip().lower() == "true"
    except Exception:
        return False


def is_process_trusted(exe_path: str) -> bool:
    """Return True if the process is in a trusted location or signed."""
    if not exe_path or not Path(exe_path).exists():
        return False
    if _is_trusted_path(exe_path):
        return True
    if sys.platform == "win32":
        return _check_signature_win(exe_path)
    return False


def resolve_asn(ip: str) -> str:
    """Resolve an IP to a hostname or ASN hint. Uses reverse DNS."""
    if ip.startswith(("127.", "10.", "0.")) or ip == "::1":
        return "private"
    if ip.startswith("192.168."):
        return "private"
    if ip.startswith("172."):
        second = int(ip.split(".")[1])
        if 16 <= second <= 31:
            return "private"
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def enumerate_connections() -> list[ConnectionRecord]:
    """Get all established TCP connections with owning process info."""
    records = []
    for conn in psutil.net_connections(kind="tcp"):
        if conn.status != "ESTABLISHED" or not conn.raddr:
            continue
        pid = conn.pid or 0
        name = ""
        exe = ""
        if pid:
            try:
                p = psutil.Process(pid)
                name = p.name()
                exe = p.exe() or ""
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name = f"<pid:{pid}>"
        records.append(ConnectionRecord(
            pid=pid, process_name=name, exe_path=exe,
            local_addr=conn.laddr.ip, local_port=conn.laddr.port,
            remote_addr=conn.raddr.ip, remote_port=conn.raddr.port,
            status=conn.status, is_c2_port=conn.raddr.port in C2_PORTS,
        ))
    return records


def flag_c2(records: list[ConnectionRecord]) -> list[ConnectionRecord]:
    """Return connections going to known C2 ports."""
    return [r for r in records if r.is_c2_port]


def flag_suspicious(records: list[ConnectionRecord]) -> list[ConnectionRecord]:
    """Flag connections from untrusted or oddly-located processes."""
    hits = []
    for rec in records:
        if not rec.exe_path or not is_process_trusted(rec.exe_path):
            tmp_markers = ("temp", "tmp", "appdata\\local\\temp", "/tmp")
            if rec.exe_path and any(m in rec.exe_path.lower() for m in tmp_markers):
                rec.is_suspicious_process = True
                hits.append(rec)
            elif not rec.exe_path or not is_process_trusted(rec.exe_path):
                rec.is_suspicious_process = True
                hits.append(rec)
    return hits


def detect_beaconing(duration_sec: float = 60.0, poll_rate: float = 2.0) -> list[BeaconCandidate]:
    """Watch connections over time and flag regular-interval (beaconing) patterns."""
    seen: dict[tuple, list[float]] = defaultdict(list)
    names: dict[tuple, str] = {}

    deadline = time.monotonic() + duration_sec
    while time.monotonic() < deadline:
        now = time.time()
        try:
            for conn in psutil.net_connections(kind="tcp"):
                if conn.status != "ESTABLISHED" or not conn.raddr:
                    continue
                key = (conn.raddr.ip, conn.raddr.port, conn.pid or 0)
                seen[key].append(now)
                if key not in names and conn.pid:
                    try:
                        names[key] = psutil.Process(conn.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        names[key] = f"<pid:{conn.pid}>"
        except (psutil.AccessDenied, PermissionError):
            pass
        left = deadline - time.monotonic()
        time.sleep(min(poll_rate, max(left, 0.1)))

    results = []
    for key, stamps in seen.items():
        deduped = [stamps[0]]
        for t in stamps[1:]:
            if t - deduped[-1] > 0.5:
                deduped.append(t)
        if len(deduped) < MIN_BEACON_SAMPLES:
            continue
        intervals = [deduped[i + 1] - deduped[i] for i in range(len(deduped) - 1)]
        avg = sum(intervals) / len(intervals)
        if avg < 1.0:
            continue
        std = (sum((x - avg) ** 2 for x in intervals) / len(intervals)) ** 0.5
        jitter = std / avg if avg else 1.0
        if jitter <= BEACON_JITTER_THRESHOLD:
            addr, port, pid = key
            results.append(BeaconCandidate(
                remote_addr=addr, remote_port=port, pid=pid,
                process_name=names.get(key, ""),
                interval_sec=round(avg, 2),
                jitter_pct=round(jitter * 100, 1),
                sample_count=len(deduped),
            ))
    return results


def analyze(
    check_beaconing: bool = False,
    beacon_duration: float = 60.0,
    resolve_asns: bool = True,
) -> AnalysisResult:
    """Run the full analysis pipeline."""
    t0 = time.monotonic()
    conns = enumerate_connections()
    c2 = flag_c2(conns)
    sus = flag_suspicious(conns)

    if resolve_asns:
        cache: dict[str, str] = {}
        for r in conns:
            if r.remote_addr not in cache:
                cache[r.remote_addr] = resolve_asn(r.remote_addr)
            r.asn_info = cache[r.remote_addr]

    beacons = detect_beaconing(duration_sec=beacon_duration) if check_beaconing else []
    return AnalysisResult(
        connections=conns, c2_flagged=c2, suspicious_procs=sus,
        beacon_candidates=beacons, scan_time=round(time.monotonic() - t0, 2),
    )


def print_report(result: AnalysisResult) -> None:
    """Print a human-readable summary."""
    sep = "=" * 70
    print(f"\n{sep}")
    print(f"  Network Analysis  ({len(result.connections)} established TCP connections)")
    print(f"  Completed in {result.scan_time}s")
    print(sep)

    if result.c2_flagged:
        print(f"\n[!] C2 PORT HITS ({len(result.c2_flagged)}):")
        for r in result.c2_flagged:
            print(f"    {r.process_name} (PID {r.pid}) -> "
                  f"{r.remote_addr}:{r.remote_port} [{r.asn_info}]")

    if result.suspicious_procs:
        print(f"\n[!] SUSPICIOUS PROCESSES ({len(result.suspicious_procs)}):")
        for r in result.suspicious_procs:
            tag = "no exe" if not r.exe_path else "untrusted"
            print(f"    {r.process_name} (PID {r.pid}) -> "
                  f"{r.remote_addr}:{r.remote_port} .  {tag}")
            if r.exe_path:
                print(f"      path: {r.exe_path}")

    if result.beacon_candidates:
        print(f"\n[!] BEACONING ({len(result.beacon_candidates)}):")
        for b in result.beacon_candidates:
            print(f"    {b.process_name} (PID {b.pid}) -> "
                  f"{b.remote_addr}:{b.remote_port}")
            print(f"      interval={b.interval_sec}s jitter={b.jitter_pct}% "
                  f"samples={b.sample_count}")

    print(f"\n{'PID':<8} {'Process':<25} {'Remote':<30} ASN/Host")
    print(f"{'-'*8} {'-'*25} {'-'*30} {'-'*30}")
    for r in result.connections:
        flags = ""
        if r.is_c2_port:
            flags += " [C2]"
        if r.is_suspicious_process:
            flags += " [SUS]"
        print(f"{r.pid:<8} {r.process_name:<25} "
              f"{r.remote_addr}:{r.remote_port:<6} {r.asn_info}{flags}")
    print()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Network connection analyzer")
    ap.add_argument("--beacon", action="store_true", help="Enable beacon detection")
    ap.add_argument("--beacon-time", type=float, default=60.0)
    ap.add_argument("--no-asn", action="store_true", help="Skip reverse DNS")
    args = ap.parse_args()

    res = analyze(
        check_beaconing=args.beacon,
        beacon_duration=args.beacon_time,
        resolve_asns=not args.no_asn,
    )
    print_report(res)