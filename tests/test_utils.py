"""Tests for core utility functions."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.utils import (
    normalize_url,
    get_base_url,
    encode_payload,
    is_valid_url,
    sanitize_param,
    build_finding,
    build_injection_url,
)


def test_normalize_url_adds_scheme():
    assert normalize_url("example.com").startswith("http")


def test_normalize_url_keeps_https():
    result = normalize_url("https://example.com/path")
    assert result.startswith("https://")


def test_get_base_url():
    assert get_base_url("https://example.com/path?q=1") == "https://example.com"


def test_encode_payload_url():
    result = encode_payload("<script>", "url")
    assert "<" not in result


def test_encode_payload_base64():
    result = encode_payload("test", "base64")
    assert result == "dGVzdA=="


def test_encode_payload_html():
    result = encode_payload("<script>&", "html")
    assert "&lt;" in result
    assert "&amp;" in result


def test_is_valid_url():
    assert is_valid_url("https://example.com") is True
    assert is_valid_url("http://example.com/path") is True
    assert is_valid_url("not-a-url") is False
    assert is_valid_url("ftp://example.com") is False


def test_sanitize_param():
    assert sanitize_param("username") == "username"
    assert sanitize_param("user<script>") == "userscript"
    assert sanitize_param("param.name-1") == "param.name-1"


def test_build_finding():
    finding = build_finding(
        vuln_type="XSS",
        url="https://example.com",
        param="q",
        payload="<script>alert(1)</script>",
        severity="High",
        confidence=85,
        evidence={"status_code": 200},
        cwe="CWE-79",
        cvss=6.1,
        owasp="A7:2017",
    )
    assert finding["vuln_type"] == "XSS"
    assert finding["severity"] == "High"
    assert finding["confidence"] == 85
    assert finding["cwe"] == "CWE-79"
    assert "timestamp" in finding


# ── Injection URL builder tests ────────────────────────────────

def test_build_injection_url_get_basic():
    """GET injection URL should embed payload in query string."""
    result = build_injection_url(
        "http://example.com/search?q=test", "q", "' OR 1=1--", "GET"
    )
    assert "example.com/search?" in result
    assert "q=" in result
    # The payload should be URL-encoded in the query string
    assert "OR" in result or "1%3D1" in result


def test_build_injection_url_get_no_existing_params():
    """GET injection URL should add parameter even if URL has no query string."""
    result = build_injection_url(
        "http://example.com/page", "id", "1", "GET"
    )
    assert "id=1" in result


def test_build_injection_url_post():
    """POST injection URL should include [POST: param=payload] suffix."""
    result = build_injection_url(
        "http://example.com/login", "user", "admin'--", "POST"
    )
    assert "[POST:" in result
    assert "user=admin'--" in result
    assert "http://example.com/login" in result


def test_build_injection_url_preserves_other_params():
    """GET injection URL should preserve existing params."""
    result = build_injection_url(
        "http://example.com/search?q=test&page=1", "q", "<script>alert(1)</script>", "GET"
    )
    assert "page=" in result
    assert "q=" in result


def test_build_injection_url_xss_payload():
    """Injection URL with XSS payload should be buildable."""
    result = build_injection_url(
        "http://example.com/?name=john", "name",
        '<script>alert(1)</script>', "GET"
    )
    assert "name=" in result
    # Script tag should be URL-encoded
    assert "script" in result.lower()


def test_build_injection_url_sqli_payload():
    """Injection URL with SQLi payload should be buildable."""
    result = build_injection_url(
        "http://example.com/api?id=5", "id",
        "' UNION SELECT NULL,NULL-- -", "GET"
    )
    assert "id=" in result
    assert "UNION" in result or "union" in result.lower()
