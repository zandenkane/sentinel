"""Certificate store auditor for Windows Trusted Root CA stores."""
# All Rights Reserved. Proprietary and confidential.

from __future__ import annotations

import json
import platform
import subprocess
import sys
from base64 import b64decode
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

KNOWN_CAS = [
    "microsoft", "digicert", "globalsign", "comodo", "entrust",
    "verisign", "thawte", "geotrust", "godaddy", "sectigo",
    "usertrust", "baltimore", "starfield", "amazontrust", "amazon",
    "identrust", "letsencrypt", "isrg", "buypass", "certum",
    "actalis", "quovadis", "secom", "affirmtrust", "trustwave",
    "ssl.com", "certigna", "t-systems", "telesec", "swisscom",
]

MAX_VALIDITY_YEARS = 20
RECENT_DAYS = 30


@dataclass
class CertFinding:
    thumbprint: str
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    has_private_key: bool
    store: str
    added_time: datetime | None
    flags: list[str] = field(default_factory=list)


def _ps_enumerate() -> list[dict]:
    """Pull certs from LocalMachine and CurrentUser Root stores via PowerShell."""
    ps_script = """
    $results = @()
    foreach ($loc in @('LocalMachine', 'CurrentUser')) {
        $path = "Cert:\\$loc\\Root"
        if (Test-Path $path) {
            Get-ChildItem $path | ForEach-Object {
                $results += [PSCustomObject]@{
                    Thumbprint = $_.Thumbprint
                    HasPrivateKey = $_.HasPrivateKey
                    Raw = [Convert]::ToBase64String($_.RawData)
                    Store = $loc
                }
            }
        }
    }
    $results | ConvertTo-Json -Compress
    """
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
        capture_output=True, text=True, timeout=30,
    )
    if proc.returncode != 0:
        print(f"[!] PowerShell error: {proc.stderr.strip()}", file=sys.stderr)
        return []
    raw = proc.stdout.strip()
    if not raw:
        return []
    data = json.loads(raw)
    # Single-object result comes back as a dict, not a list
    return data if isinstance(data, list) else [data]


def _registry_added_time(thumbprint: str, store: str) -> datetime | None:
    """Read the registry key last-write time as a proxy for when the cert was added."""
    import winreg
    hive = winreg.HKEY_LOCAL_MACHINE if store == "LocalMachine" else winreg.HKEY_CURRENT_USER
    path = rf"SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\{thumbprint}"
    try:
        key = winreg.OpenKey(hive, path)
        info = winreg.QueryInfoKey(key)
        winreg.CloseKey(key)
        # info[2] is last-write FILETIME in 100ns intervals since 1601-01-01
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        return epoch + timedelta(microseconds=info[2] // 10)
    except OSError:
        return None


def _is_known_ca(name: x509.Name) -> bool:
    """Check if the subject name matches a known major CA by O, CN, or DC."""
    parts: list[str] = []
    for oid in (NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME, NameOID.DOMAIN_COMPONENT):
        try:
            parts.extend(a.value for a in name.get_attributes_for_oid(oid))
        except Exception:
            pass
    combined = " ".join(parts).lower()
    return any(re.search(r"" + re.escape(ca) + r"", combined) for ca in KNOWN_CAS)


def _get_org(name: x509.Name) -> str:
    """Extract the Organization (O) or CN attribute from an x509 Name."""
    try:
        attrs = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if attrs:
            return attrs[0].value
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else ""
    except Exception:
        return ""


def _has_server_auth_eku(cert: x509.Certificate) -> bool:
    """Check if the cert has an explicit Server Authentication EKU."""
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        return ExtendedKeyUsageOID.SERVER_AUTH in eku.value
    except x509.ExtensionNotFound:
        return True  # no EKU = valid for all purposes per RFC 5280


def audit_root_store() -> list[CertFinding]:
    """Audit the Windows Trusted Root CA store and return flagged certs."""
    if platform.system() != "Windows":
        print("[!] This auditor only supports Windows.", file=sys.stderr)
        return []

    entries = _ps_enumerate()
    now = datetime.now(timezone.utc)
    findings: list[CertFinding] = []

    for entry in entries:
        thumbprint = entry["Thumbprint"]
        has_pk = entry["HasPrivateKey"]
        store = entry["Store"]

        try:
            der = b64decode(entry["Raw"])
            cert = x509.load_der_x509_certificate(der)
        except Exception as exc:
            print(f"[!] Skipping {thumbprint}: {exc}", file=sys.stderr)
            continue

        added = _registry_added_time(thumbprint, store)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        subj_str = cert.subject.rfc4514_string()
        issuer_str = cert.issuer.rfc4514_string()

        flags: list[str] = []

        # Flag 1: interception-capable .  self-signed + Server Auth EKU + private key
        if cert.subject == cert.issuer and _has_server_auth_eku(cert) and has_pk:
            flags.append("INTERCEPT_CAPABLE: self-signed with ServerAuth EKU and private key")

        # Flag 2: not from a known major CA
        org = _get_org(cert.subject)
        if not _is_known_ca(cert.subject):
            flags.append(f"UNKNOWN_CA: '{org}' not in known CA list")

        # Flag 3: recently added (within 30 days)
        check_time = added if added else not_before
        if (now - check_time).days <= RECENT_DAYS:
            source = "registry timestamp" if added else "NotBefore (fallback)"
            flags.append(f"RECENTLY_ADDED: {check_time.date()} ({source})")

        # Flag 4: unusually long validity (>20 years)
        validity_years = (not_after - not_before).days / 365.25
        if validity_years > MAX_VALIDITY_YEARS:
            flags.append(f"LONG_VALIDITY: {validity_years:.1f} years")

        if flags:
            findings.append(CertFinding(
                thumbprint=thumbprint, subject=subj_str, issuer=issuer_str,
                not_before=not_before, not_after=not_after,
                has_private_key=has_pk, store=store, added_time=added,
                flags=flags,
            ))

    return findings


def main() -> None:
    findings = audit_root_store()
    if not findings:
        print("[+] No suspicious certificates found.")
        return

    print(f"[!] Found {len(findings)} flagged certificate(s):\n")
    for f in findings:
        print(f"  Thumbprint : {f.thumbprint}")
        print(f"  Subject    : {f.subject}")
        print(f"  Issuer     : {f.issuer}")
        print(f"  Valid      : {f.not_before.date()} .  {f.not_after.date()}")
        print(f"  PrivateKey : {f.has_private_key}")
        print(f"  Store      : {f.store}")
        if f.added_time:
            print(f"  Added      : {f.added_time.date()}")
        for flag in f.flags:
            print(f"  >> {flag}")
        print()


if __name__ == "__main__":
    main()
