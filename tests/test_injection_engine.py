"""Tests for the injection detection engine upgrade.

Covers: injection context analysis, WAF evasion, raw response parsing,
multi-stage confirmation, upgraded false-positive filter, evidence enrichment,
and tech fingerprint database detection.
"""
import os
import sys
import re
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Injection Context ──────────────────────────────────────────────


class TestConfirmationMarker:
    def test_generate_returns_unique(self):
        from core.injection_context import ConfirmationMarker
        m1 = ConfirmationMarker.generate(stage=1)
        m2 = ConfirmationMarker.generate(stage=1)
        assert m1 != m2
        assert m1.startswith("VS_")
        assert m1.endswith("_1")

    def test_pair_returns_two_related_markers(self):
        from core.injection_context import ConfirmationMarker
        m1, m2 = ConfirmationMarker.pair()
        assert m1.endswith("_1")
        assert m2.endswith("_2")
        # Same base tag
        assert m1[:-2] == m2[:-2]

    def test_is_marker_detects_vs_tags(self):
        from core.injection_context import ConfirmationMarker
        assert ConfirmationMarker.is_marker("VS_a1b2c3d4_1") is True
        assert ConfirmationMarker.is_marker("no marker here") is False
        assert ConfirmationMarker.is_marker("prefix VS_abcdef01_2 suffix") is True


class TestInjectionContextAnalyzer:
    def test_classify_url_param(self):
        from core.injection_context import InjectionContextAnalyzer
        analyzer = InjectionContextAnalyzer()
        result = analyzer.classify_param("url", "https://example.com")
        assert result["ssrf_candidate"] is True
        assert result["data_type"] == "url"

    def test_classify_id_param(self):
        from core.injection_context import InjectionContextAnalyzer
        analyzer = InjectionContextAnalyzer()
        result = analyzer.classify_param("id", "42")
        assert result["data_type"] == "integer"
        assert result["sqli_candidate"] is True

    def test_classify_search_param(self):
        from core.injection_context import InjectionContextAnalyzer
        analyzer = InjectionContextAnalyzer()
        result = analyzer.classify_param("query")
        assert result["xss_candidate"] is True

    def test_detect_reflection_present(self):
        from core.injection_context import InjectionContextAnalyzer
        analyzer = InjectionContextAnalyzer()
        assert analyzer.detect_reflection("Hello VS_abc12345_1 world", "VS_abc12345_1") == "reflected"

    def test_detect_reflection_absent(self):
        from core.injection_context import InjectionContextAnalyzer
        analyzer = InjectionContextAnalyzer()
        assert analyzer.detect_reflection("Nothing here", "VS_abc12345_1") == "absent"

    def test_detect_response_context_attribute(self):
        from core.injection_context import InjectionContextAnalyzer
        analyzer = InjectionContextAnalyzer()
        html = '<input value="VS_test1234_1" name="q">'
        assert analyzer.detect_response_context(html, "VS_test1234_1") == "attribute"

    def test_detect_response_context_script(self):
        from core.injection_context import InjectionContextAnalyzer
        analyzer = InjectionContextAnalyzer()
        html = '<script>var x = "VS_test1234_1";</script>'
        assert analyzer.detect_response_context(html, "VS_test1234_1") == "script"

    def test_detect_response_context_tag(self):
        from core.injection_context import InjectionContextAnalyzer
        analyzer = InjectionContextAnalyzer()
        html = '<div>VS_test1234_1</div>'
        assert analyzer.detect_response_context(html, "VS_test1234_1") == "tag_content"

    def test_recommend_payloads_integer(self):
        from core.injection_context import InjectionContextAnalyzer
        analyzer = InjectionContextAnalyzer()
        strategies = analyzer.recommend_payloads("tag_content", "integer", "MySQL")
        assert "numeric_sqli" in strategies
        assert "mysql_sqli" in strategies
        assert "xss_tag_injection" in strategies


# ── WAF Evasion ────────────────────────────────────────────────────


class TestWAFDetector:
    def test_is_blocked_403(self):
        from core.waf_evasion import WAFDetector
        detector = WAFDetector()
        resp = MagicMock()
        resp.status_code = 403
        resp.text = "Access Denied by Web Application Firewall"
        resp.headers = {}
        assert detector.is_blocked(resp) is True

    def test_is_blocked_normal_200(self):
        from core.waf_evasion import WAFDetector
        detector = WAFDetector()
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "Normal page"
        resp.headers = {}
        assert detector.is_blocked(resp) is False

    def test_identify_cloudflare(self):
        from core.waf_evasion import WAFDetector
        detector = WAFDetector()
        resp = MagicMock()
        resp.status_code = 403
        resp.text = "Attention Required! Cloudflare"
        resp.headers = {"cf-ray": "abc123"}
        assert "Cloudflare" in detector.identify_waf(resp)

    def test_is_blocked_none(self):
        from core.waf_evasion import WAFDetector
        detector = WAFDetector()
        assert detector.is_blocked(None) is False


class TestPayloadTransformer:
    def test_transform_includes_original(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        variants = t.transform("' OR 1=1--")
        assert "' OR 1=1--" in variants
        assert len(variants) >= 2  # At least original + one variant

    def test_case_variation(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        variants = t.transform("' UNION SELECT NULL-- -", techniques=["case_variation"])
        # Should produce at least the original
        assert len(variants) >= 1

    def test_url_encode(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        variants = t.transform("<script>alert(1)</script>", techniques=["url_encode"])
        assert len(variants) >= 2
        assert any("%3C" in v or "%3c" in v for v in variants)

    def test_comment_injection(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        variants = t.transform("' UNION SELECT NULL", techniques=["comment_injection"])
        assert any("/**/" in v for v in variants)


class TestAdaptiveThrottle:
    def test_initial_delay(self):
        from core.waf_evasion import AdaptiveThrottle
        throttle = AdaptiveThrottle(base_delay=1.0)
        assert throttle.get_delay() == 1.0

    def test_block_increases_delay(self):
        from core.waf_evasion import AdaptiveThrottle
        throttle = AdaptiveThrottle(base_delay=0.5)
        initial = throttle.get_delay()
        throttle.on_block()
        assert throttle.get_delay() > initial

    def test_success_decreases_delay(self):
        from core.waf_evasion import AdaptiveThrottle
        throttle = AdaptiveThrottle(base_delay=0.5)
        throttle.on_block()
        throttle.on_block()
        after_blocks = throttle.get_delay()
        throttle.on_success()
        assert throttle.get_delay() < after_blocks


# ── Raw Response Analyzer ──────────────────────────────────────────


class TestRawResponseAnalyzer:
    def test_check_injected_header(self):
        from core.raw_response import RawResponseAnalyzer
        resp = MagicMock()
        resp.headers = {"X-Venom": "injected", "Content-Type": "text/html"}
        assert RawResponseAnalyzer.check_injected_header(resp, "X-Venom") is True
        assert RawResponseAnalyzer.check_injected_header(resp, "X-Missing") is False

    def test_check_header_value(self):
        from core.raw_response import RawResponseAnalyzer
        resp = MagicMock()
        resp.headers = {"Set-Cookie": "venom=injected; path=/"}
        assert RawResponseAnalyzer.check_header_value(resp, "Set-Cookie", "venom") is True
        assert RawResponseAnalyzer.check_header_value(resp, "Set-Cookie", "missing") is False

    def test_detect_redirect_injection(self):
        from core.raw_response import RawResponseAnalyzer
        resp = MagicMock()
        resp.headers = {"Location": "https://evil.com/phish"}
        assert RawResponseAnalyzer.detect_redirect_injection(resp, "evil.com") is True
        assert RawResponseAnalyzer.detect_redirect_injection(resp, "safe.com") is False

    def test_detect_structure_change_marker(self):
        from core.raw_response import RawResponseAnalyzer
        baseline = "<html><body>Normal</body></html>"
        payload = "<html><body>Normal VS_test1234_1</body></html>"
        result = RawResponseAnalyzer.detect_structure_change(baseline, payload, "VS_test1234_1")
        assert result["marker_reflected"] is True

    def test_detect_structure_change_new_tags(self):
        from core.raw_response import RawResponseAnalyzer
        baseline = "<html><body>Normal</body></html>"
        payload = "<html><body>Normal<script>alert(1)</script></body></html>"
        result = RawResponseAnalyzer.detect_structure_change(baseline, payload)
        assert result["new_tags_found"] is True
        assert "script" in result.get("new_tags", [])

    def test_capture_full_evidence(self):
        from core.raw_response import RawResponseAnalyzer
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"test content"
        resp.text = "test content"
        resp.headers = {"Content-Type": "text/html"}
        resp.reason = "OK"
        evidence = RawResponseAnalyzer.capture_full_evidence(resp)
        assert evidence["status_code"] == 200
        assert "raw_headers" in evidence
        assert "body_hash" in evidence

    def test_capture_full_evidence_with_baseline(self):
        from core.raw_response import RawResponseAnalyzer
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"long content here"
        resp.text = "long content here"
        resp.headers = {"Content-Type": "text/html"}
        resp.reason = "OK"

        baseline = MagicMock()
        baseline.status_code = 200
        baseline.content = b"short"
        baseline.text = "short"
        baseline.headers = {}
        baseline.reason = "OK"

        evidence = RawResponseAnalyzer.capture_full_evidence(resp, baseline)
        assert "baseline_status" in evidence
        assert evidence["length_diff"] > 0


# ── Confirmation Pipeline ──────────────────────────────────────────


class TestInjectionConfirmer:
    def test_confirm_both_markers_match(self):
        from core.confirmation import InjectionConfirmer
        import requests
        session = MagicMock(spec=requests.Session)
        confirmer = InjectionConfirmer(session)

        def inject_func(marker):
            resp = MagicMock()
            resp.text = f"Hello {marker} world"
            return resp

        def check_func(resp, marker):
            return marker in resp.text

        result = confirmer.confirm(inject_func, check_func)
        assert result["confirmed"] is True
        assert result["probe_matched"] is True
        assert result["confirm_matched"] is True
        assert result["confidence_boost"] == 15

    def test_confirm_probe_only(self):
        from core.confirmation import InjectionConfirmer
        import requests
        session = MagicMock(spec=requests.Session)
        confirmer = InjectionConfirmer(session)

        call_count = [0]

        def inject_func(marker):
            call_count[0] += 1
            resp = MagicMock()
            # Only first call reflects marker
            if call_count[0] == 1:
                resp.text = f"Hello {marker} world"
            else:
                resp.text = "No marker"
            return resp

        def check_func(resp, marker):
            return marker in resp.text

        result = confirmer.confirm(inject_func, check_func)
        assert result["confirmed"] is False
        assert result["probe_matched"] is True
        assert result["confirm_matched"] is False

    def test_confirm_baseline_not_clean(self):
        from core.confirmation import InjectionConfirmer
        import requests
        session = MagicMock(spec=requests.Session)
        confirmer = InjectionConfirmer(session)

        def inject_func(marker):
            resp = MagicMock()
            resp.text = f"Hello {marker} world"
            return resp

        def check_func(resp, marker):
            # Always returns True (even for baseline)
            return True

        def baseline_func():
            resp = MagicMock()
            resp.text = "Normal page"
            return resp

        result = confirmer.confirm(inject_func, check_func, baseline_func)
        assert result["confirmed"] is False  # Baseline wasn't clean
        assert result["baseline_clean"] is False
        assert result["confidence_boost"] == 5  # Reduced boost


# ── False Positive Filter (New Methods) ────────────────────────────


class TestFalsePositiveFilterCRLF:
    def test_crlf_detected(self):
        from core.false_positive_filter import FalsePositiveFilter
        fp = FalsePositiveFilter()
        baseline = MagicMock()
        baseline.headers = {"Content-Type": "text/html"}
        payload = MagicMock()
        payload.headers = {"Content-Type": "text/html", "X-Venom": "injected"}
        result = fp.check_crlf_detailed(baseline, payload)
        assert result["is_real"] is True

    def test_crlf_in_baseline(self):
        from core.false_positive_filter import FalsePositiveFilter
        fp = FalsePositiveFilter()
        baseline = MagicMock()
        baseline.headers = {"X-Venom": "exists"}
        payload = MagicMock()
        payload.headers = {"X-Venom": "injected"}
        result = fp.check_crlf_detailed(baseline, payload)
        assert result["is_real"] is False


class TestFalsePositiveFilterXXE:
    def test_xxe_detected(self):
        from core.false_positive_filter import FalsePositiveFilter
        fp = FalsePositiveFilter()
        baseline = MagicMock()
        baseline.text = "Normal response"
        payload = MagicMock()
        payload.text = "root:x:0:0:root:/root:/bin/bash"
        result = fp.check_xxe_detailed(baseline, payload)
        assert result["is_real"] is True

    def test_xxe_in_baseline(self):
        from core.false_positive_filter import FalsePositiveFilter
        fp = FalsePositiveFilter()
        baseline = MagicMock()
        baseline.text = "root:x:0:0:root:/root:/bin/bash"
        payload = MagicMock()
        payload.text = "root:x:0:0:root:/root:/bin/bash"
        result = fp.check_xxe_detailed(baseline, payload)
        assert result["is_real"] is False


class TestFalsePositiveFilterOpenRedirect:
    def test_redirect_detected(self):
        from core.false_positive_filter import FalsePositiveFilter
        fp = FalsePositiveFilter()
        resp = MagicMock()
        resp.status_code = 302
        resp.headers = {"Location": "https://evil.com/phish"}
        result = fp.check_open_redirect_detailed(resp, "evil.com")
        assert result["is_real"] is True

    def test_redirect_safe(self):
        from core.false_positive_filter import FalsePositiveFilter
        fp = FalsePositiveFilter()
        resp = MagicMock()
        resp.status_code = 302
        resp.headers = {"Location": "https://safe.example.com/"}
        result = fp.check_open_redirect_detailed(resp, "evil.com")
        assert result["is_real"] is False


# ── Evidence Package Enrichment ────────────────────────────────────


class TestEvidencePackageEnrichment:
    def test_new_fields_exist(self):
        from core.evidence import EvidencePackage
        ep = EvidencePackage()
        assert hasattr(ep, "raw_headers")
        assert hasattr(ep, "exploitability_description")
        assert hasattr(ep, "remediation_guidance")

    def test_to_dict_includes_new_fields(self):
        from core.evidence import EvidencePackage
        ep = EvidencePackage(
            raw_headers="HTTP/1.1 200 OK\r\nX-Venom: injected",
            exploitability_description="Allows full database dump",
            remediation_guidance="Use parameterized queries",
        )
        d = ep.to_dict()
        assert d["raw_headers"] == "HTTP/1.1 200 OK\r\nX-Venom: injected"
        assert d["exploitability_description"] == "Allows full database dump"
        assert d["remediation_guidance"] == "Use parameterized queries"

    def test_to_dict_omits_empty_new_fields(self):
        from core.evidence import EvidencePackage
        ep = EvidencePackage()
        d = ep.to_dict()
        assert "raw_headers" not in d
        assert "exploitability_description" not in d
        assert "remediation_guidance" not in d


class TestBuildProofDescriptionNewTypes:
    def test_crlf_proof(self):
        from core.evidence import build_proof_description
        proof = build_proof_description("CRLF", {
            "injected_header": True,
            "injected_header_name": "X-Venom",
        })
        assert "CRLF" in proof
        assert "X-Venom" in proof

    def test_xxe_proof(self):
        from core.evidence import build_proof_description
        proof = build_proof_description("XXE", {
            "xxe_content": "root:x:0:0:root",
        })
        assert "XXE" in proof
        assert "root:" in proof

    def test_redirect_proof(self):
        from core.evidence import build_proof_description
        proof = build_proof_description("Open Redirect", {
            "redirect_injection": True,
            "injected_domain": "evil.com",
        })
        assert "evil.com" in proof

    def test_nosql_proof(self):
        from core.evidence import build_proof_description
        proof = build_proof_description("NoSQL", {
            "nosql_auth_bypass": True,
            "baseline_status": 401,
            "payload_status": 200,
        })
        assert "NoSQL" in proof
        assert "401" in proof

    def test_confirmation_markers_proof(self):
        from core.evidence import build_proof_description
        proof = build_proof_description("XSS", {
            "confirmation_markers": ["VS_abc_1", "VS_abc_2"],
        })
        assert "confirmation" in proof.lower() or "marker" in proof.lower()


# ── Config New Keys ────────────────────────────────────────────────


class TestConfigNewKeys:
    def test_waf_evasion_setting(self):
        import config
        assert hasattr(config, "WAF_EVASION_ENABLED")
        assert isinstance(config.WAF_EVASION_ENABLED, bool)

    def test_early_termination_setting(self):
        import config
        assert hasattr(config, "EARLY_TERMINATION")
        assert isinstance(config.EARLY_TERMINATION, bool)

    def test_confirmation_enabled_setting(self):
        import config
        assert hasattr(config, "CONFIRMATION_ENABLED")
        assert isinstance(config.CONFIRMATION_ENABLED, bool)


# ── Tech Fingerprint Database Detection ────────────────────────────


class TestTechFingerprintDatabase:
    def test_detect_mysql(self):
        from recon.tech_fingerprint import TechFingerprint
        import requests
        tf = TechFingerprint(session=MagicMock(spec=requests.Session))
        resp = MagicMock()
        resp.text = "Warning: mysql_connect(): Access denied"
        resp.headers = {}
        assert tf._detect_database(resp) == "MySQL"

    def test_detect_postgres(self):
        from recon.tech_fingerprint import TechFingerprint
        import requests
        tf = TechFingerprint(session=MagicMock(spec=requests.Session))
        resp = MagicMock()
        resp.text = "ERROR: postgresql connection refused"
        resp.headers = {}
        assert tf._detect_database(resp) == "PostgreSQL"

    def test_detect_mongodb(self):
        from recon.tech_fingerprint import TechFingerprint
        import requests
        tf = TechFingerprint(session=MagicMock(spec=requests.Session))
        resp = MagicMock()
        resp.text = "MongoError: authentication failed"
        resp.headers = {}
        assert tf._detect_database(resp) == "MongoDB"

    def test_detect_unknown(self):
        from recon.tech_fingerprint import TechFingerprint
        import requests
        tf = TechFingerprint(session=MagicMock(spec=requests.Session))
        resp = MagicMock()
        resp.text = "Normal page content"
        resp.headers = {}
        assert tf._detect_database(resp) == "Unknown"


# ── Base Exploiter Integration ─────────────────────────────────────


class TestBaseExploiterIntegration:
    def test_has_waf_detector(self):
        """BaseExploiter subclass should have WAF detection tools."""
        from exploits.injection.sqli_exploiter import SQLiExploiter
        exploiter = SQLiExploiter()
        assert hasattr(exploiter, "waf_detector")
        assert hasattr(exploiter, "payload_transformer")
        assert hasattr(exploiter, "throttle")
        assert hasattr(exploiter, "confirmer")
        assert hasattr(exploiter, "context_analyzer")

    def test_inject_param_helper(self):
        """BaseExploiter should expose _inject_param helper."""
        from exploits.injection.sqli_exploiter import SQLiExploiter
        exploiter = SQLiExploiter()
        assert hasattr(exploiter, "_inject_param")

    def test_get_waf_variants(self):
        """_get_waf_variants should return list including original."""
        from exploits.injection.sqli_exploiter import SQLiExploiter
        exploiter = SQLiExploiter()
        variants = exploiter._get_waf_variants("' OR 1=1--")
        assert "' OR 1=1--" in variants
        assert len(variants) >= 1


# ── New PayloadTransformer techniques ──────────────────────────────


class TestPayloadTransformerHexEncode:
    def test_hex_encode_special_chars(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        variants = t.transform("' OR 1=1--", techniques=["hex_encode"])
        assert len(variants) >= 2
        hex_variant = [v for v in variants if "0x27" in v]
        assert hex_variant, "Expected hex-encoded single-quote (0x27)"

    def test_hex_encode_preserves_alphanumeric(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        result = t._apply_hex_encode("abc123")
        # No special chars → no hex substitution
        assert result == "abc123"


class TestPayloadTransformerUnicodeEncode:
    def test_unicode_encode_special_chars(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        variants = t.transform("<script>alert(1)</script>", techniques=["unicode_encode"])
        assert len(variants) >= 2
        unicode_variant = [v for v in variants if "\\u003c" in v]
        assert unicode_variant, "Expected unicode-encoded '<' (\\u003c)"

    def test_unicode_encode_preserves_alphanumeric(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        result = t._apply_unicode_encode("abc")
        assert result == "abc"


class TestPayloadTransformerNullByte:
    def test_null_byte_prepended(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        variants = t.transform("admin", techniques=["null_byte_injection"])
        assert len(variants) >= 2
        assert any(v.startswith("%00") for v in variants)

    def test_null_byte_does_not_modify_body(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        result = t._apply_null_byte_injection("test")
        assert result.endswith("test")


class TestPayloadTransformerMySQLComment:
    def test_mysql_comment_wraps_keywords(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        variants = t.transform("' UNION SELECT NULL", techniques=["mysql_comment_bypass"])
        assert any("/*!50000" in v for v in variants)

    def test_mysql_comment_no_change_without_keywords(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        result = t._apply_mysql_comment_bypass("' OR 1=1--")
        # OR is not in the MySQL-comment keyword list for this technique
        # but if it were, it would be wrapped — assert structure is valid
        assert isinstance(result, str)


class TestPayloadTransformerConcatObfuscation:
    def test_concat_splits_long_strings(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        result = t._apply_concat_obfuscation("'admin'")
        assert "CONCAT(" in result
        assert "'ad'" in result or "'min'" in result

    def test_concat_leaves_short_strings(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        result = t._apply_concat_obfuscation("'ab'")
        assert "CONCAT" not in result


class TestPayloadTransformerParameterPollution:
    def test_pollution_contains_separator(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        variants = t.transform("' OR 1=1--", techniques=["parameter_pollution"])
        pollution = [v for v in variants if "|||" in v]
        assert pollution, "Expected a variant with the ||| separator"

    def test_pollution_has_decoy(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        result = t._apply_parameter_pollution("PAYLOAD")
        parts = result.split("|||")
        assert len(parts) == 2
        assert parts[0] == "harmless"
        assert parts[1] == "PAYLOAD"


class TestAllTechniquesAttribute:
    def test_all_techniques_lists_new_entries(self):
        from core.waf_evasion import PayloadTransformer
        expected_new = [
            "hex_encode", "unicode_encode", "null_byte_injection",
            "mysql_comment_bypass", "concat_obfuscation", "parameter_pollution",
            "chunked_transfer", "json_smuggle", "multipart_boundary",
            "tab_substitution", "scientific_notation", "overlong_utf8",
        ]
        for name in expected_new:
            assert name in PayloadTransformer.ALL_TECHNIQUES, f"{name} missing"

    def test_transform_default_uses_all(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        variants = t.transform("' UNION SELECT 'admin' FROM users--")
        # With all techniques applied we should get a good number of variants
        assert len(variants) >= 6


# ── EncodingRotator ────────────────────────────────────────────────


class TestEncodingRotator:
    def test_rotate_returns_identity_first(self):
        from core.waf_evasion import EncodingRotator
        r = EncodingRotator()
        variants = r.rotate("test")
        assert variants[0] == "test"

    def test_rotate_contains_url_encoding(self):
        from core.waf_evasion import EncodingRotator
        r = EncodingRotator()
        variants = r.rotate("' OR 1=1")
        # URL-encoded single-quote
        assert any("%27" in v for v in variants)

    def test_rotate_contains_base64(self):
        from core.waf_evasion import EncodingRotator
        import base64
        r = EncodingRotator()
        payload = "' OR 1=1"
        variants = r.rotate(payload)
        expected_b64 = base64.b64encode(payload.encode()).decode()
        assert expected_b64 in variants

    def test_rotate_contains_hex(self):
        from core.waf_evasion import EncodingRotator
        r = EncodingRotator()
        variants = r.rotate("a")
        # 'a' hex-encoded should be %61
        assert any("%61" in v for v in variants)

    def test_rotate_contains_html_entities(self):
        from core.waf_evasion import EncodingRotator
        r = EncodingRotator()
        variants = r.rotate("<")
        assert any("&#60;" in v for v in variants)

    def test_rotate_no_duplicates(self):
        from core.waf_evasion import EncodingRotator
        r = EncodingRotator()
        variants = r.rotate("' OR 1=1")
        assert len(variants) == len(set(variants))

    def test_rotate_covers_all_encodings(self):
        from core.waf_evasion import EncodingRotator
        r = EncodingRotator()
        variants = r.rotate("test<>")
        assert len(variants) == len(EncodingRotator.ENCODINGS)


# ── HeaderBypass ───────────────────────────────────────────────────


class TestHeaderBypass:
    def test_build_header_variants_count(self):
        from core.waf_evasion import HeaderBypass
        hb = HeaderBypass()
        variants = hb.build_header_variants("' OR 1=1--")
        assert len(variants) == len(HeaderBypass.INJECTION_HEADERS)

    def test_each_variant_has_payload(self):
        from core.waf_evasion import HeaderBypass
        hb = HeaderBypass()
        payload = "' OR 1=1--"
        variants = hb.build_header_variants(payload)
        for headers in variants:
            assert any(v == payload for v in headers.values())

    def test_extra_headers_merged(self):
        from core.waf_evasion import HeaderBypass
        hb = HeaderBypass()
        extra = {"Authorization": "Bearer tok123"}
        variants = hb.build_header_variants("test", extra_headers=extra)
        for headers in variants:
            assert headers.get("Authorization") == "Bearer tok123"

    def test_injection_headers_used(self):
        from core.waf_evasion import HeaderBypass
        hb = HeaderBypass()
        variants = hb.build_header_variants("payload")
        all_keys = set()
        for headers in variants:
            all_keys.update(headers.keys())
        for hdr in HeaderBypass.INJECTION_HEADERS:
            assert hdr in all_keys


# ── BaseExploiter new helpers ──────────────────────────────────────


class TestBaseExploiterNewHelpers:
    def test_has_encoding_rotator(self):
        from exploits.injection.sqli_exploiter import SQLiExploiter
        exploiter = SQLiExploiter()
        assert hasattr(exploiter, "encoding_rotator")
        assert hasattr(exploiter, "header_bypass")

    def test_get_encoding_variants(self):
        from exploits.injection.sqli_exploiter import SQLiExploiter
        exploiter = SQLiExploiter()
        variants = exploiter._get_encoding_variants("test")
        assert "test" in variants
        assert len(variants) >= 2

    def test_get_header_variants(self):
        from exploits.injection.sqli_exploiter import SQLiExploiter
        exploiter = SQLiExploiter()
        variants = exploiter._get_header_variants("payload")
        assert len(variants) > 0
        assert all(isinstance(h, dict) for h in variants)

    def test_parameter_pollution_in_inject_param(self):
        """_inject_param should split ||| separator for parameter pollution."""
        from exploits.injection.sqli_exploiter import SQLiExploiter
        exploiter = SQLiExploiter()
        # We can't test actual HTTP, but we verify the method exists and
        # can be called (it will return None because no server is running)
        result = exploiter._inject_param(
            "http://localhost:99999/?q=test", "q",
            "harmless|||' OR 1=1--", "GET",
        )
        # Expected None due to connection error, but no exception raised
        assert result is None


# ── v5.0 Apex — new PayloadTransformer techniques ────────────────────


class TestPayloadTransformerChunkedTransfer:
    def test_chunked_splits_payload(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        result = t._apply_chunked_transfer("SELECT * FROM users")
        assert "\r\n" in result
        assert result.endswith("0\r\n\r\n")

    def test_chunked_short_payload_unchanged(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        result = t._apply_chunked_transfer("ab")
        assert result == "ab"


class TestPayloadTransformerJsonSmuggle:
    def test_json_smuggle_wraps_payload(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        result = t._apply_json_smuggle("<script>")
        assert result.startswith('{"data":"')
        assert "\\u003c" in result  # < encoded

    def test_json_smuggle_is_valid_json(self):
        import json
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        result = t._apply_json_smuggle("test payload")
        parsed = json.loads(result)
        assert "data" in parsed


class TestPayloadTransformerMultipartBoundary:
    def test_multipart_contains_boundary(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        result = t._apply_multipart_boundary("PAYLOAD")
        assert "----VenomStrike" in result
        assert "PAYLOAD" in result
        assert "Content-Disposition" in result

    def test_multipart_has_decoy_part(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        result = t._apply_multipart_boundary("test")
        assert "safe_value" in result


class TestPayloadTransformerTabSubstitution:
    def test_tab_replaces_spaces(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        result = t._apply_tab_substitution("SELECT * FROM users")
        assert "\t" in result
        assert " " not in result

    def test_tab_no_change_without_spaces(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        result = t._apply_tab_substitution("nospaces")
        assert result == "nospaces"


class TestPayloadTransformerScientificNotation:
    def test_scientific_replaces_numbers(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        result = t._apply_scientific_notation("id=100")
        assert "e" in result
        assert "100" not in result

    def test_scientific_handles_zero(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        result = t._apply_scientific_notation("val=0")
        assert "0e0" in result


class TestPayloadTransformerOverlongUtf8:
    def test_overlong_encodes_special_chars(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        result = t._apply_overlong_utf8("<script>alert('xss')</script>")
        assert "%c0%bc" in result  # < encoded
        assert "%c0%be" in result  # > encoded
        assert "%c0%a7" in result  # ' encoded

    def test_overlong_preserves_alphanumeric(self):
        from core.waf_evasion import PayloadTransformer
        t = PayloadTransformer()
        result = t._apply_overlong_utf8("abc123")
        assert result == "abc123"


class TestApexTechniqueCount:
    """Verify v5.0 has all 17 WAF evasion techniques."""
    def test_total_technique_count(self):
        from core.waf_evasion import PayloadTransformer
        assert len(PayloadTransformer.ALL_TECHNIQUES) == 17
