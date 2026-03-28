"""Tests for the evidence and verification system."""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.evidence import (
    EvidencePackage,
    RequestTrace,
    capture_request_trace,
    build_proof_description,
    VERIFIED_CONFIRMED,
    VERIFIED_LIKELY,
    VERIFIED_SUSPICIOUS,
    VERIFIED_UNVERIFIED,
    VERIFIED_FALSE_POSITIVE,
)


def test_evidence_package_creation():
    """EvidencePackage should create with defaults."""
    ep = EvidencePackage()
    assert ep.verification_status == VERIFIED_UNVERIFIED
    assert ep.proof_description == ""
    assert ep.retest_confirmations == 0


def test_evidence_package_fingerprint():
    """Fingerprint should be deterministic for same vuln_type+url+param."""
    ep1 = EvidencePackage(vuln_type="SQLi", tested_url="http://example.com", tested_param="id")
    ep2 = EvidencePackage(vuln_type="SQLi", tested_url="http://example.com", tested_param="id")
    assert ep1.compute_fingerprint() == ep2.compute_fingerprint()


def test_evidence_package_different_fingerprints():
    """Different params should produce different fingerprints."""
    ep1 = EvidencePackage(vuln_type="SQLi", tested_url="http://example.com", tested_param="id")
    ep2 = EvidencePackage(vuln_type="SQLi", tested_url="http://example.com", tested_param="name")
    assert ep1.compute_fingerprint() != ep2.compute_fingerprint()


def test_evidence_package_to_dict():
    """to_dict should include all key fields."""
    ep = EvidencePackage(
        vuln_type="XSS",
        tested_url="http://test.com",
        tested_param="q",
        tested_payload="<script>",
        verification_status=VERIFIED_LIKELY,
        proof_description="Reflected unescaped",
        proof_data={"reflected_payload": True},
    )
    d = ep.to_dict()
    assert d["vuln_type"] == "XSS"
    assert d["verification_status"] == "likely"
    assert d["proof_description"] == "Reflected unescaped"
    assert d["proof_data"]["reflected_payload"] is True


def test_evidence_package_with_traces():
    """to_dict should include baseline and payload_request when set."""
    baseline = RequestTrace(method="GET", url="http://test.com", status_code=200, response_length=1000)
    payload_req = RequestTrace(method="GET", url="http://test.com?q=payload", status_code=500, response_length=2000)
    ep = EvidencePackage(baseline=baseline, payload_request=payload_req)
    d = ep.to_dict()
    assert "baseline" in d
    assert d["baseline"]["status_code"] == 200
    assert d["payload_request"]["status_code"] == 500


def test_request_trace_to_dict():
    """RequestTrace should serialize to dict."""
    rt = RequestTrace(method="POST", url="http://test.com", status_code=302, response_length=500)
    d = rt.to_dict()
    assert d["method"] == "POST"
    assert d["status_code"] == 302


def test_build_proof_description_sqli():
    """Proof description should describe SQL error detection."""
    proof = build_proof_description("SQLi", {
        "error_pattern": r"sql syntax",
    })
    assert "SQL error" in proof
    assert "payload" in proof.lower()


def test_build_proof_description_xss():
    """Proof description should describe XSS reflection."""
    proof = build_proof_description("XSS", {
        "reflected_payload": True,
        "reflected_part": "<script",
    })
    assert "reflected" in proof.lower() or "UNESCAPED" in proof


def test_build_proof_description_timing():
    """Proof description should describe timing anomaly."""
    proof = build_proof_description("SQLi Blind", {
        "timing_diff": 5.3,
        "baseline_time": 0.2,
    })
    assert "5.3" in proof
    assert "0.2" in proof


def test_build_proof_description_lfi():
    """Proof description should describe file content indicator."""
    proof = build_proof_description("LFI", {
        "file_content_indicator": "Unix /etc/passwd root entry",
    })
    assert "file content" in proof.lower()


def test_build_proof_description_cmd():
    """Proof description should describe command output."""
    proof = build_proof_description("CMDi", {
        "command_output": "Unix id command output",
    })
    assert "command output" in proof.lower()


def test_build_proof_description_ssrf():
    """Proof description should describe SSRF metadata detection."""
    proof = build_proof_description("SSRF", {
        "metadata_content": "ami-id",
    })
    assert "metadata" in proof.lower()


def test_build_proof_description_empty():
    """Proof description should handle empty proof data gracefully."""
    proof = build_proof_description("Unknown", {})
    assert "detected" in proof.lower() or "vulnerability" in proof.lower()


def test_verification_status_constants():
    """Verification status constants should be lowercase strings."""
    assert VERIFIED_CONFIRMED == "confirmed"
    assert VERIFIED_LIKELY == "likely"
    assert VERIFIED_SUSPICIOUS == "suspicious"
    assert VERIFIED_UNVERIFIED == "unverified"
    assert VERIFIED_FALSE_POSITIVE == "false_positive"
