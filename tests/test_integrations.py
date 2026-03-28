"""Tests for integration modules (without requiring external tools)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def test_nmap_scanner_import():
    """NmapScanner should import without error."""
    from integrations.nmap_scanner import NmapScanner
    scanner = NmapScanner()
    assert scanner is not None


def test_nuclei_runner_import():
    """NucleiRunner should import without error."""
    from integrations.nuclei_runner import NucleiRunner
    runner = NucleiRunner()
    assert runner is not None


def test_cve_lookup_import():
    """CVELookup should import without error."""
    from integrations.cve_lookup import CVELookup
    lookup = CVELookup()
    assert lookup is not None


def test_shodan_recon_import():
    """ShodanRecon should import without error."""
    from integrations.shodan_recon import ShodanRecon
    recon = ShodanRecon()
    assert recon is not None


def test_zap_scanner_import():
    """ZAPScanner should import without error."""
    from integrations.zap_scanner import ZAPScanner
    scanner = ZAPScanner()
    assert scanner is not None


def test_cve_lookup_parse():
    """CVELookup._parse_cve should handle empty data gracefully."""
    from integrations.cve_lookup import CVELookup
    lookup = CVELookup()
    result = lookup._parse_cve({})
    assert result["cve_id"] == ""
    assert result["cvss_score"] == 0.0


def test_nuclei_parse_empty():
    """NucleiRunner should handle empty output."""
    from integrations.nuclei_runner import NucleiRunner
    runner = NucleiRunner()
    result = runner._parse_results("")
    assert result == []


def test_nmap_parse_empty():
    """NmapScanner._parse_results should return empty hosts for unknown target."""
    from integrations.nmap_scanner import NmapScanner
    scanner = NmapScanner()
    # Pass an invalid target name — scanner has no results to parse
    result = scanner._parse_results("invalid-target-host")
    assert result["hosts"] == []


# ── Amass integration tests ────────────────────────────────────────


def test_amass_enum_import():
    """AmassEnum should import without error."""
    from integrations.amass_enum import AmassEnum
    enum = AmassEnum()
    assert enum is not None


def test_amass_not_available_by_default():
    """AmassEnum.is_available should return False when disabled."""
    from integrations.amass_enum import AmassEnum
    enum = AmassEnum()
    # AMASS_ENABLED defaults to false
    assert enum.is_available() is False


def test_amass_parse_json_lines():
    """AmassEnum._parse_json_lines should extract subdomain names."""
    from integrations.amass_enum import AmassEnum
    lines = '{"name":"a.example.com"}\n{"name":"b.example.com"}\n'
    result = AmassEnum._parse_json_lines(lines)
    assert "a.example.com" in result
    assert "b.example.com" in result
    assert result == sorted(result)


def test_amass_parse_json_lines_empty():
    """AmassEnum._parse_json_lines should handle empty input."""
    from integrations.amass_enum import AmassEnum
    assert AmassEnum._parse_json_lines("") == []


def test_amass_parse_json_details():
    """AmassEnum._parse_json_details should return structured dicts."""
    from integrations.amass_enum import AmassEnum
    import json
    line = json.dumps({
        "name": "sub.example.com",
        "domain": "example.com",
        "addresses": [{"ip": "1.2.3.4"}],
        "sources": ["dns"],
    })
    result = AmassEnum._parse_json_details(line)
    assert len(result) == 1
    assert result[0]["name"] == "sub.example.com"
    assert result[0]["addresses"] == ["1.2.3.4"]


def test_amass_passive_returns_empty_when_disabled():
    """passive_enum should return empty list when Amass is disabled."""
    from integrations.amass_enum import AmassEnum
    enum = AmassEnum()
    result = enum.passive_enum("example.com")
    assert result == []


# ── Wappalyzer integration tests ──────────────────────────────────


def test_wappalyzer_import():
    """WappalyzerFingerprint should import without error."""
    from integrations.wappalyzer_fingerprint import WappalyzerFingerprint
    fp = WappalyzerFingerprint()
    assert fp is not None


def test_wappalyzer_not_available_by_default():
    """WappalyzerFingerprint.is_available should return False when disabled."""
    from integrations.wappalyzer_fingerprint import WappalyzerFingerprint
    fp = WappalyzerFingerprint()
    # WAPPALYZER_ENABLED defaults to false
    assert fp.is_available() is False


def test_wappalyzer_signatures_populated():
    """WappalyzerFingerprint should have built-in signatures."""
    from integrations.wappalyzer_fingerprint import WappalyzerFingerprint
    assert len(WappalyzerFingerprint.SIGNATURES) >= 20


def test_wappalyzer_analyse_response():
    """_analyse_response should detect technologies from a mock response."""
    from unittest.mock import MagicMock
    from integrations.wappalyzer_fingerprint import WappalyzerFingerprint
    import requests

    fp = WappalyzerFingerprint()
    fp._enabled = True

    resp = MagicMock(spec=requests.Response)
    resp.headers = {"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.2"}
    resp.text = "<html><head></head><body>Hello</body></html>"
    resp.cookies = MagicMock()
    resp.cookies.__iter__ = MagicMock(return_value=iter([]))

    detections = fp._analyse_response(resp)
    names = [d["name"] for d in detections]
    assert "Nginx" in names
    assert "PHP" in names


def test_wappalyzer_fingerprint_returns_empty_when_disabled():
    """fingerprint should return empty list when disabled."""
    from integrations.wappalyzer_fingerprint import WappalyzerFingerprint
    fp = WappalyzerFingerprint()
    result = fp.fingerprint("http://example.com")
    assert result == []
