"""TLS ClientHello JA3 fingerprinting for C2 detection on port 443.

Computes JA3 hashes from ClientHello packets (scapy), checks them against
known C2 fingerprints, inspects server certs (TLS 1.2 only .  1.3 encrypts
the Certificate message), and maps connections to processes via psutil.

Requires: scapy + Npcap (Windows), psutil, cryptography.
MITRE ATT&CK: T1573.002  (Encrypted Channel: Asymmetric Cryptography)
"""
from __future__ import annotations
import hashlib
import logging
import struct
from typing import Optional
import psutil
from sentinel.finding import Finding

log = logging.getLogger(__name__)

# RFC 8701 GREASE values .  strip from ciphers, extensions, curves
GREASE: set[int] = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a,
    0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}

# Known C2 JA3 hashes (salesforce/ja3, C2-Profiler, public TI).
# Sliver/PoshC2/Havoc/Brute Ratel lack reliably sourced public JA3 hashes;
# add verified hashes from lab captures or TI feeds to extend coverage.
C2_JA3_DB: dict[str, list[str]] = {
    "Cobalt Strike": ["72a589da586844d7f0818ce684948eea",
                       "a0e9f5d64349fb13191bc781f81f42e1"],
    "Metasploit":    ["5d65ea3fb1d4aa7d826733d2f2cbbb1d"],
    # "Sliver": [], "PoshC2": [], "Havoc": [], "Brute Ratel": [],
}
_HASH_TO_C2: dict[str, str] = {h: fw for fw, hs in C2_JA3_DB.items() for h in hs}
MITRE_ID = "T1573.002"
_HS = 0x16; _CH = 0x01; _CERT = 0x0B  # TLS content/handshake types
_EXT_SNI = 0x00; _EXT_GROUPS = 0x0A; _EXT_ECPF = 0x0B

# .  ClientHello parser + JA3 . . . . . . . . . . . . -

def _u16(buf: bytes, off: int) -> int:
    return struct.unpack("!H", buf[off:off + 2])[0]


def _parse_client_hello(payload: bytes) -> Optional[dict]:
    """Parse a TLS record into ClientHello fields for JA3. None on failure."""
    if len(payload) < 6 or payload[0] != _HS:
        return None
    hs = payload[5:5 + _u16(payload, 3)]
    if len(hs) < 4 or hs[0] != _CH:
        return None
    b = hs[4:]
    if len(b) < 34:
        return None
    version = _u16(b, 0)
    pos = 34 + 1 + b[34]                      # skip random + session_id
    if pos + 2 > len(b):
        return None
    cs_len = _u16(b, pos); pos += 2
    if pos + cs_len > len(b):
        return None
    ciphers = [_u16(b, pos + i) for i in range(0, cs_len, 2)
               if _u16(b, pos + i) not in GREASE]
    pos += cs_len
    if pos >= len(b):
        return None
    pos += 1 + b[pos]                          # skip compression
    exts: list[int] = []; curves: list[int] = []; pf: list[int] = []; sni = ""
    if pos + 2 <= len(b):
        end = pos + 2 + _u16(b, pos); pos += 2
        while pos + 4 <= end and pos + 4 <= len(b):
            et = _u16(b, pos); el = _u16(b, pos + 2)
            ed = b[pos + 4:pos + 4 + el]; pos += 4 + el
            if et in GREASE:
                continue
            exts.append(et)
            if et == _EXT_SNI and len(ed) >= 5:
                nl = _u16(ed, 3)
                if 5 + nl <= len(ed):
                    sni = ed[5:5 + nl].decode("ascii", errors="replace")
            elif et == _EXT_GROUPS and len(ed) >= 2:
                gl = _u16(ed, 0)
                curves = [_u16(ed, i) for i in range(2, 2 + gl, 2)
                          if i + 2 <= len(ed) and _u16(ed, i) not in GREASE]
            elif et == _EXT_ECPF and len(ed) >= 1:
                pf = [ed[i] for i in range(1, 1 + ed[0]) if i < len(ed)]
    return {"version": version, "ciphers": ciphers, "extensions": exts,
            "curves": curves, "point_formats": pf, "sni": sni}


def compute_ja3(parsed: dict) -> tuple[str, str]:
    """Return (ja3_string, ja3_md5) from parsed ClientHello fields."""
    s = ",".join([str(parsed["version"]),
                  "-".join(str(c) for c in parsed["ciphers"]),
                  "-".join(str(e) for e in parsed["extensions"]),
                  "-".join(str(g) for g in parsed["curves"]),
                  "-".join(str(p) for p in parsed["point_formats"])])
    return s, hashlib.md5(s.encode()).hexdigest()


def lookup_c2(ja3_hash: str) -> Optional[str]:
    """Return C2 framework name if hash is known, else None."""
    return _HASH_TO_C2.get(ja3_hash)

# .  PID mapping (live only) . . . . . . . . . . . . 

def _map_pid(src_ip: str, src_port: int) -> tuple[int, str]:
    """Map (src_ip, src_port) to (pid, process_name). (0, '') on miss."""
    try:
        for c in psutil.net_connections(kind="tcp"):
            if c.laddr and c.laddr.port == src_port:
                if c.laddr.ip in (src_ip, "0.0.0.0", "::"):
                    pid = c.pid or 0
                    if pid:
                        try:
                            return pid, psutil.Process(pid).name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            return pid, f"<pid:{pid}>"
    except (psutil.AccessDenied, PermissionError):
        pass
    return 0, ""

# .  Certificate checks (TLS 1.2 only) . . . . . . . . . -

def _check_cert(cert_der: bytes, sni: str) -> list[str]:
    """Return list of issue strings for a DER certificate. Empty = clean."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception:
        return []
    issues: list[str] = []
    if cert.subject == cert.issuer:
        issues.append("self-signed certificate")
    days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
    if days > 365:  # will flag some legit ~398-day certs; tune as needed
        issues.append(f"validity {days}d (>365)")
    try:
        cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        issues.append("no SAN extension")
    if sni:
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn and isinstance(cn[0].value, str):
                if cn[0].value.lower() != sni.lower():
                    issues.append(f"CN '{cn[0].value}' != SNI '{sni}'")
        except Exception:
            pass
    return issues


def _extract_cert(payload: bytes) -> Optional[bytes]:
    """Pull the first DER cert from a TLS 1.2 Certificate handshake record.

    Only fires when the Certificate message starts at byte 0 of the TCP
    payload and fits in a single segment.  Multi-record segments (e.g.
    ServerHello + Certificate in one payload) and reassembly-spanning
    certs are not handled .  this is a best-effort heuristic."""
    if len(payload) < 5 or payload[0] != _HS:
        return None
    hs = payload[5:5 + _u16(payload, 3)]
    if len(hs) < 4 or hs[0] != _CERT:
        return None
    b = hs[4:]
    if len(b) < 6:
        return None
    cl = struct.unpack("!I", b"\x00" + b[3:6])[0]
    return b[6:6 + cl] if 6 + cl <= len(b) else None

# .  Packet processing core . . . . . . . . . . . . -

def _process_pkt(ip_src: str, ip_dst: str, sport: int, dport: int,
                 raw: bytes, findings: list[Finding],
                 sni_map: dict, live: bool) -> None:
    """Handle one TCP payload: extract JA3, check certs, map PID."""
    if len(raw) < 6 or raw[0] != _HS:
        return
    parsed = _parse_client_hello(raw)
    if parsed is not None:
        ja3_str, ja3_hash = compute_ja3(parsed)
        fk = (ip_src, sport, ip_dst, dport)
        if parsed["sni"]:
            sni_map[fk] = parsed["sni"]
        c2 = lookup_c2(ja3_hash)
        if c2:
            pid, pname = _map_pid(ip_src, sport) if live else (0, "")
            findings.append(Finding(
                module="tls_fingerprint", severity="critical",
                title=f"Known C2 JA3: {c2}",
                detail=f"JA3 {ja3_hash} matches {c2}. "
                       f"{'Process: ' + pname + ' ' if pname else ''}"
                       f"{ip_src}:{sport} -> {ip_dst}:{dport}",
                evidence=f"ja3={ja3_hash} ja3_string={ja3_str}",
                mitre_id=MITRE_ID, pid=pid))
    cert_der = _extract_cert(raw)
    if cert_der:
        sni = sni_map.get((ip_dst, dport, ip_src, sport), "")
        issues = _check_cert(cert_der, sni)
        if issues:
            pid, pname = _map_pid(ip_dst, dport) if live else (0, "")
            findings.append(Finding(
                module="tls_fingerprint", severity="high",
                title="Suspicious TLS certificate",
                detail=f"{ip_src}:{sport}: " + "; ".join(issues),
                evidence=f"sni={sni} dst={ip_dst}:{dport}",
                mitre_id=MITRE_ID, pid=pid))

# .  Public API . . . . . . . . . . . . . . . -

def _ip_addrs(pkt) -> Optional[tuple[str, str]]:  # type: ignore[no-untyped-def]
    """Extract (src, dst) IP strings from IPv4 or IPv6 layer. None if absent."""
    try:
        from scapy.all import IP, IPv6
        if pkt.haslayer(IP):
            return pkt[IP].src, pkt[IP].dst
        if pkt.haslayer(IPv6):
            return pkt[IPv6].src, pkt[IPv6].dst
    except Exception:
        pass
    return None


def analyze_pcap(pcap_path: str) -> list[Finding]:
    """Analyze a pcap file for C2 JA3 hashes and suspicious certificates."""
    try:
        from scapy.all import rdpcap, TCP
    except ImportError:
        return [Finding(module="tls_fingerprint", title="Missing scapy",
                severity="info", detail="pip install scapy", evidence="",
                mitre_id=MITRE_ID)]
    findings: list[Finding] = []
    sni_map: dict[tuple, str] = {}
    try:
        pkts = rdpcap(pcap_path)
    except Exception as exc:
        return [Finding(module="tls_fingerprint", title="pcap read error",
                severity="info", detail=str(exc), evidence=pcap_path,
                mitre_id=MITRE_ID)]
    for p in pkts:
        if not p.haslayer(TCP) or not p[TCP].payload:
            continue
        addrs = _ip_addrs(p)
        if not addrs:
            continue
        _process_pkt(addrs[0], addrs[1], p[TCP].sport, p[TCP].dport,
                     bytes(p[TCP].payload), findings, sni_map, live=False)
    return findings


def analyze_live(iface: Optional[str] = None, duration: int = 30,
                 bpf_filter: str = "tcp port 443") -> list[Finding]:
    """Sniff live TLS traffic for C2 fingerprints. Needs Npcap on Windows."""
    try:
        from scapy.all import sniff, TCP
    except ImportError:
        return [Finding(module="tls_fingerprint", severity="info",
                title="Missing scapy/Npcap",
                detail="pip install scapy + https://npcap.com",
                evidence="ImportError", mitre_id=MITRE_ID)]
    findings: list[Finding] = []
    sni_map: dict[tuple, str] = {}

    def _cb(p):  # type: ignore[no-untyped-def]
        if not p.haslayer(TCP) or not p[TCP].payload:
            return
        addrs = _ip_addrs(p)
        if not addrs:
            return
        _process_pkt(addrs[0], addrs[1], p[TCP].sport, p[TCP].dport,
                     bytes(p[TCP].payload), findings, sni_map, live=True)

    log.info("Capturing %ds on %s [%s]", duration, iface or "default", bpf_filter)
    try:
        sniff(iface=iface, filter=bpf_filter, prn=_cb,
              timeout=duration, store=False)
    except PermissionError:
        findings.append(Finding(module="tls_fingerprint", severity="info",
            title="Need admin", detail="Run as Administrator for live capture",
            evidence="PermissionError", mitre_id=MITRE_ID))
    except OSError as exc:
        findings.append(Finding(module="tls_fingerprint", severity="info",
            title="Capture error", detail=f"Npcap installed? {exc}",
            evidence=str(exc), mitre_id=MITRE_ID))
    return findings


def scan(pcap_path: Optional[str] = None, live_duration: int = 30,
         iface: Optional[str] = None) -> list[Finding]:
    """Unified entry point: pcap file analysis or live capture."""
    if pcap_path:
        return analyze_pcap(pcap_path)
    return analyze_live(iface=iface, duration=live_duration)


if __name__ == "__main__":
    import argparse
    import sys
    logging.basicConfig(level=logging.DEBUG,
                        format="%(asctime)s %(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description="TLS JA3 C2 detector")
    ap.add_argument("--pcap", help="Pcap file for offline analysis")
    ap.add_argument("--live", type=int, default=30, help="Live capture seconds")
    ap.add_argument("--iface", help="Network interface")
    args = ap.parse_args()
    results = scan(pcap_path=args.pcap, live_duration=args.live, iface=args.iface)
    if not results:
        print("[+] No suspicious TLS fingerprints detected.")
        sys.exit(0)
    for f in results:
        print(f.format_finding(), end="\n\n")
    sys.exit(1)
