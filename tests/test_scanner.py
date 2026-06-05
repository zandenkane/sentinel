"""Tests for sentinel detection modules.

Covers: Finding dataclass, config loading, ARP parsing, network C2 detection,
persistence registry parsing, DNS entropy/DGA detection, certificate EKU checking.
All OS calls are mocked so tests run on any platform.
"""
import json
import types
from collections import namedtuple
from unittest.mock import MagicMock, patch
import pytest

from sentinel.finding import Finding
from sentinel.config import Config, load_config
from sentinel import arp, persistence
from sentinel.dnsmon import shannon_entropy, detect_dga, DGA_ENTROPY_THRESHOLD

# .  Finding dataclass . . . . . . . -

class TestFinding:
    def test_create_and_to_dict(self):
        f = Finding(module="test_mod", title="Bad process", severity="high",
                    detail="ran from temp", evidence="/tmp/evil.exe",
                    mitre_id="T1059", path="/tmp/evil.exe", pid=1234)
        d = f.to_dict()
        assert d["module"] == "test_mod"
        assert d["severity"] == "high"
        assert d["pid"] == 1234
        assert d["mitre_id"] == "T1059"

    def test_to_json_roundtrip(self):
        f = Finding(module="net", title="C2", severity="critical",
                    detail="port 4444", evidence="1.2.3.4:4444")
        loaded = json.loads(f.to_json())
        assert loaded["module"] == "net"
        assert loaded["severity"] == "critical"

    def test_invalid_severity_falls_back_to_info(self):
        f = Finding(module="x", title="t", severity="bogus", detail="d", evidence="e")
        assert f.severity == "info"

# .  Config loading . . . . . . . . 

class TestConfig:
    def test_defaults_no_file(self):
        cfg = load_config(path="/nonexistent/sentinel.yaml")
        assert isinstance(cfg, Config)
        assert cfg.beacon_window_sec == 60.0
        assert 4444 in cfg.c2_ports
        assert cfg.output_format == "text"
        assert cfg.verbosity == 1

    def test_load_from_yaml(self, tmp_path):
        f = tmp_path / "sentinel.yaml"
        f.write_text("beacon_window_sec: 120\nc2_ports:\n  - 9999\n  - 31337\n"
                     "output_format: json\nverbosity: 2\n", encoding="utf-8")
        cfg = load_config(path=str(f))
        assert cfg.beacon_window_sec == 120.0
        assert cfg.c2_ports == [9999, 31337]
        assert cfg.output_format == "json"
        assert cfg.verbosity == 2
        assert cfg.scan_timeout_sec == 300.0  # unchanged default

# .  ARP table parsing . . . . . . . -

ARP_OUTPUT = (
    "Interface: 192.168.1.1 . - 0x3\n"
    "  Internet Address      Physical Address      Type\n"
    "  192.168.1.1            aa-bb-cc-dd-ee-01     dynamic\n"
    "  192.168.1.50           aa-bb-cc-dd-ee-02     dynamic\n"
    "  192.168.1.255          ff-ff-ff-ff-ff-ff     static\n"
    "  224.0.0.22             01-00-5e-00-00-16     static\n"
)

class TestArp:
    @patch("sentinel.arp.subprocess.check_output", return_value=ARP_OUTPUT)
    def test_read_arp_table(self, _mock):
        table = arp.read_arp_table()
        assert "192.168.1.255" not in table  # broadcast filtered
        assert "224.0.0.22" not in table      # multicast filtered
        assert table["192.168.1.1"] == "aa:bb:cc:dd:ee:01"
        assert table["192.168.1.50"] == "aa:bb:cc:dd:ee:02"

    def test_detect_shared_macs(self):
        table = {"192.168.1.10": "aa:bb:cc:dd:ee:01",
                 "192.168.1.20": "aa:bb:cc:dd:ee:01",
                 "192.168.1.30": "aa:bb:cc:dd:ee:02"}
        alerts = arp.detect_shared_macs(table)
        assert len(alerts) == 1
        assert alerts[0]["mac"] == "aa:bb:cc:dd:ee:01"
        assert set(alerts[0]["ips"]) == {"192.168.1.10", "192.168.1.20"}

# .  Network C2 port detection . . . . . . -

try:
    import psutil  # noqa: F401
    from sentinel import network
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

Addr = namedtuple("Addr", ["ip", "port"])
FakeConn = namedtuple("FakeConn", ["laddr", "raddr", "status", "pid"])

@pytest.mark.skipif(not HAS_PSUTIL, reason="psutil not installed")
class TestNetworkC2:
    def _conns(self):
        return [
            FakeConn(Addr("10.0.0.5", 55000), Addr("45.33.32.156", 4444), "ESTABLISHED", 0),
            FakeConn(Addr("10.0.0.5", 55001), Addr("142.250.80.46", 443), "ESTABLISHED", 0),
            FakeConn(Addr("10.0.0.5", 55002), Addr("1.2.3.4", 6666), "SYN_SENT", 0),
        ]

    @patch("sentinel.network.psutil.net_connections")
    def test_c2_port_flagged(self, mock_nc):
        mock_nc.return_value = self._conns()
        records = network.enumerate_connections()
        c2 = network.flag_c2(records)
        assert len(c2) == 1
        assert c2[0].remote_port == 4444
        assert c2[0].is_c2_port is True

    @patch("sentinel.network.psutil.net_connections")
    def test_non_c2_port_clean(self, mock_nc):
        mock_nc.return_value = [
            FakeConn(Addr("10.0.0.5", 55001), Addr("142.250.80.46", 443), "ESTABLISHED", 0),
        ]
        c2 = network.flag_c2(network.enumerate_connections())
        assert len(c2) == 0

# .  Persistence registry key parsing . . . . . . 

class TestPersistenceRegVals:
    def _fake_winreg(self, entries):
        fake = types.ModuleType("winreg")
        fake.KEY_READ = 0x20019
        fake.HKEY_LOCAL_MACHINE = 0x80000002
        fake.HKEY_CURRENT_USER = 0x80000001
        fake.OpenKey = MagicMock(return_value=MagicMock())
        fake.CloseKey = MagicMock()
        def enum_value(_key, idx):
            if idx < len(entries):
                return (entries[idx][0], entries[idx][1], 1)
            raise OSError("no more items")
        fake.EnumValue = enum_value
        return fake

    def test_reg_vals_returns_entries(self, monkeypatch):
        entries = [("MalwareLoader", r"C:\Users\Public\evil.exe"),
                   ("LegitApp", r"C:\Program Files\Good\app.exe")]
        fake = self._fake_winreg(entries)
        monkeypatch.setattr(persistence, "winreg", fake, raising=False)
        result = persistence._reg_vals(fake.HKEY_LOCAL_MACHINE,
                                       r"Software\Microsoft\Windows\CurrentVersion\Run")
        assert len(result) == 2
        assert result[0] == ("MalwareLoader", r"C:\Users\Public\evil.exe")
        assert result[1] == ("LegitApp", r"C:\Program Files\Good\app.exe")

    def test_reg_vals_empty_on_missing_key(self, monkeypatch):
        fake = types.ModuleType("winreg")
        fake.KEY_READ = 0x20019
        fake.OpenKey = MagicMock(side_effect=OSError("key not found"))
        fake.CloseKey = MagicMock()
        monkeypatch.setattr(persistence, "winreg", fake, raising=False)
        assert persistence._reg_vals(0x80000002, r"DOES\NOT\EXIST") == []

# .  DNS entropy / DGA detection . . . . . . -

class TestDnsEntropy:
    def test_uniform_single_char(self):
        assert shannon_entropy("aaaaaaaa") == 0.0

    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_legitimate_domain_low_entropy(self):
        assert shannon_entropy("google") < DGA_ENTROPY_THRESHOLD

    def test_dga_domain_high_entropy(self):
        assert shannon_entropy("a1b2c3d4e5f6g7h8") > DGA_ENTROPY_THRESHOLD

    def test_detect_dga_flags_random_domain(self):
        entries = [{"name": "google.com", "data": "1.2.3.4"},
                   {"name": "x9k2m4q7z8w1p3r5.biz", "data": "5.6.7.8"}]
        findings = detect_dga(entries)
        domains = [f.domain for f in findings]
        assert "google.com" not in domains
        assert any("x9k2m4q7z8w1p3r5" in d for d in domains)
        assert all(f.kind == "dga" for f in findings)

    def test_detect_dga_clean_list(self):
        entries = [{"name": "github.com", "data": "1.2.3.4"},
                   {"name": "docs.python.org", "data": "5.6.7.8"}]
        assert len(detect_dga(entries)) == 0

# .  Certificate EKU checking . . . . . . . 

try:
    from cryptography.x509 import ExtensionNotFound
    from cryptography.x509.oid import ExtendedKeyUsageOID
    from sentinel.certs import _has_server_auth_eku
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
class TestCertEku:
    def _cert_with_eku(self, usages):
        cert = MagicMock()
        ext = MagicMock()
        ext.value = usages
        cert.extensions.get_extension_for_class.return_value = ext
        return cert

    def _cert_no_eku(self):
        cert = MagicMock()
        cert.extensions.get_extension_for_class.side_effect = ExtensionNotFound(
            "No EKU", oid=ExtendedKeyUsageOID.SERVER_AUTH)
        return cert

    def test_server_auth_present(self):
        assert _has_server_auth_eku(self._cert_with_eku([ExtendedKeyUsageOID.SERVER_AUTH])) is True

    def test_server_auth_absent(self):
        assert _has_server_auth_eku(self._cert_with_eku([ExtendedKeyUsageOID.CLIENT_AUTH])) is False

    def test_no_eku_extension_returns_true(self):
        # RFC 5280: no EKU means valid for all purposes
        assert _has_server_auth_eku(self._cert_no_eku()) is True
