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
