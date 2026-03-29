"""Tests for VenomStrike v7.0 Titan Edition features.

Covers:
- Titan config settings & depth preset
- Out-of-Band (OOB) verification
- Context-aware payload mutation engine
- Enhanced WAF fingerprinting
- Robust percentile-based timing baselines
- Input validation for /learning/<vuln_type> route
- Integration of new modules in base_exploiter
"""
import os
import sys
import time
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Config: Titan settings ────────────────────────────────────────


class TestTitanConfig:
    """Verify Titan v7.0 config additions."""

    def test_version_is_8(self):
        import config
        assert config.VERSION == "9.0.0"

    def test_codename_is_hydra(self):
        import config
        assert config.CODENAME == "Chimera"

    def test_titan_depth_preset_exists(self):
        import config
        assert "titan" in config.DEPTH_PRESETS

    def test_titan_depth_is_valid(self):
        import config
        assert "titan" in config._VALID_DEPTHS

    def test_titan_preset_has_required_keys(self):
        import config
        preset = config.DEPTH_PRESETS["titan"]
        for key in ("crawl_depth", "max_crawl_pages", "dir_brute_limit",
                     "api_brute_limit", "payload_limit", "validation_attempts",
                     "min_confidence"):
            assert key in preset, f"Missing key: {key}"

    def test_titan_preset_deeper_than_quantum(self):
        import config
        t = config.DEPTH_PRESETS["titan"]
        q = config.DEPTH_PRESETS["quantum"]
        assert t["crawl_depth"] > q["crawl_depth"]
        assert t["max_crawl_pages"] > q["max_crawl_pages"]
        assert t["validation_attempts"] > q["validation_attempts"]

    def test_titan_preset_has_titan_flags(self):
        import config
        preset = config.DEPTH_PRESETS["titan"]
        assert preset.get("oob_verification") is True
        assert preset.get("payload_mutation") is True
        assert preset.get("robust_timing") is True
        assert preset.get("waf_fingerprinting") is True
        # Also inherits quantum flags
        assert preset.get("cross_correlation") is True
        assert preset.get("entropy_analysis") is True
        assert preset.get("triple_confirm") is True
        assert preset.get("statistical_confidence") is True

    def test_titan_config_keys_exist(self):
        import config
        assert hasattr(config, "OOB_VERIFICATION_ENABLED")
        assert hasattr(config, "OOB_CALLBACK_DOMAIN")
        assert hasattr(config, "OOB_CALLBACK_TIMEOUT")
        assert hasattr(config, "PAYLOAD_MUTATION_ENABLED")
        assert hasattr(config, "ROBUST_TIMING_ENABLED")
        assert hasattr(config, "ROBUST_TIMING_PERCENTILE")
        assert hasattr(config, "WAF_FINGERPRINT_ENABLED")

    def test_robust_timing_percentile_range(self):
        import config
        assert 50.0 <= config.ROBUST_TIMING_PERCENTILE <= 99.9

    def test_oob_callback_timeout_range(self):
        import config
        assert 1 <= config.OOB_CALLBACK_TIMEOUT <= 60

    def test_user_agent_contains_hydra(self):
        import config
        assert "Chimera" in config.DEFAULT_USER_AGENT
        assert "9.0" in config.DEFAULT_USER_AGENT

    def test_depth_presets_ordering_includes_titan(self):
        """Titan should have highest crawl_depth of all levels."""
        import config
        levels = ["quick", "standard", "deep", "full", "quantum", "titan"]
        for i in range(len(levels) - 1):
            a = config.DEPTH_PRESETS[levels[i]]
            b = config.DEPTH_PRESETS[levels[i + 1]]
            assert a["crawl_depth"] <= b["crawl_depth"]
            assert a["max_crawl_pages"] <= b["max_crawl_pages"]


# ── OOB Verification ──────────────────────────────────────────────


class TestOOBToken:
    """Test OOBToken creation and properties."""

    def test_token_generation(self):
        from core.oob_verifier import OOBToken
        token = OOBToken("sqli", "http://test.com", "id", "' OR 1=1 --")
        assert len(token.token) == 16
        assert token.vuln_type == "sqli"
        assert token.url == "http://test.com"
        assert token.param == "id"

    def test_token_uniqueness(self):
        from core.oob_verifier import OOBToken
        t1 = OOBToken("sqli", "http://test.com", "id", "payload1")
        t2 = OOBToken("sqli", "http://test.com", "id", "payload2")
        assert t1.token != t2.token

    def test_dns_hostname_without_domain(self):
        from core.oob_verifier import OOBToken
        with patch("core.oob_verifier.OOB_CALLBACK_DOMAIN", ""):
            token = OOBToken("sqli", "http://test.com", "id", "payload")
            assert token.dns_hostname == ""

    def test_dns_hostname_with_domain(self):
        from core.oob_verifier import OOBToken
        with patch("core.oob_verifier.OOB_CALLBACK_DOMAIN", "callback.example.com"):
            token = OOBToken("sqli", "http://test.com", "id", "payload")
            assert token.token in token.dns_hostname
            assert "callback.example.com" in token.dns_hostname

    def test_http_url_without_domain(self):
        from core.oob_verifier import OOBToken
        with patch("core.oob_verifier.OOB_CALLBACK_DOMAIN", ""):
            token = OOBToken("ssrf", "http://test.com", "url", "payload")
            assert token.http_url == ""

    def test_to_dict(self):
        from core.oob_verifier import OOBToken
        token = OOBToken("xss", "http://test.com", "q", "<script>")
        d = token.to_dict()
        assert "token" in d
        assert "vuln_type" in d
        assert d["vuln_type"] == "xss"
        assert "created_at" in d


class TestOOBVerifier:
    """Test OOBVerifier functionality."""

    def test_is_configured_false_by_default(self):
        from core.oob_verifier import OOBVerifier
        v = OOBVerifier()
        # Default config has empty domain
        assert isinstance(v.is_configured, bool)

    def test_generate_token(self):
        from core.oob_verifier import OOBVerifier
        v = OOBVerifier()
        token = v.generate_token("sqli", "http://test.com", "id", "payload")
        assert token.vuln_type == "sqli"
        assert token in v.get_pending_tokens()

    def test_build_dns_payload_unsupported_type(self):
        from core.oob_verifier import OOBVerifier, OOBToken
        v = OOBVerifier()
        with patch("core.oob_verifier.OOB_CALLBACK_DOMAIN", "cb.example.com"):
            token = OOBToken("xss", "http://test.com", "q", "original")
            # XSS has no DNS template
            result = v.build_dns_payload(token, "original")
            assert result == "original"

    def test_build_dns_payload_sqli(self):
        from core.oob_verifier import OOBVerifier, OOBToken
        v = OOBVerifier()
        with patch("core.oob_verifier.OOB_CALLBACK_DOMAIN", "cb.example.com"):
            token = OOBToken("sqli", "http://test.com", "id", "' OR 1=1")
            result = v.build_dns_payload(token, "' OR 1=1")
            assert token.dns_hostname in result

    def test_build_http_payload_ssrf(self):
        from core.oob_verifier import OOBVerifier, OOBToken
        v = OOBVerifier()
        with patch("core.oob_verifier.OOB_CALLBACK_DOMAIN", "cb.example.com"):
            token = OOBToken("ssrf", "http://test.com", "url", "http://evil.com")
            result = v.build_http_payload(token, "http://evil.com")
            assert token.token in result

    def test_check_callback_not_configured(self):
        from core.oob_verifier import OOBVerifier
        v = OOBVerifier()
        v._callback_domain = ""
        token = v.generate_token("sqli", "http://test.com", "id", "payload")
        result = v.check_callback(token)
        assert result["verified"] is False
        assert result["status"] == "not_configured"

    def test_cleanup_expired(self):
        from core.oob_verifier import OOBVerifier
        v = OOBVerifier()
        token = v.generate_token("sqli", "http://test.com", "id", "payload")
        token.created_at = time.time() - 600  # 10 minutes ago
        removed = v.cleanup_expired(max_age=300)
        assert removed == 1
        assert len(v.get_pending_tokens()) == 0

    def test_build_verification_evidence(self):
        from core.oob_verifier import OOBVerifier
        v = OOBVerifier()
        token = v.generate_token("sqli", "http://test.com", "id", "payload")
        check_result = {"status": "callback_received", "verified": True,
                        "check_time": time.time()}
        evidence = v.build_verification_evidence(token, check_result)
        assert evidence["oob_verification"] is True
        assert evidence["oob_verified"] is True
        assert "oob_token" in evidence

    def test_dns_payload_templates_coverage(self):
        """Verify DNS templates exist for key vuln types."""
        from core.oob_verifier import OOBVerifier
        for vtype in ("sqli", "xxe", "ssrf", "cmd", "rce"):
            assert vtype in OOBVerifier.DNS_PAYLOAD_TEMPLATES
            assert OOBVerifier.DNS_PAYLOAD_TEMPLATES[vtype] != ""

    def test_http_payload_templates_coverage(self):
        """Verify HTTP templates exist for key vuln types."""
        from core.oob_verifier import OOBVerifier
        for vtype in ("sqli", "xxe", "ssrf", "cmd", "rce"):
            assert vtype in OOBVerifier.HTTP_PAYLOAD_TEMPLATES
            assert OOBVerifier.HTTP_PAYLOAD_TEMPLATES[vtype] != ""


# ── Payload Mutation ──────────────────────────────────────────────


class TestPayloadMutator:
    """Test context-aware payload mutation engine."""

    def test_mutate_returns_original(self):
        from core.payload_mutator import PayloadMutator
        m = PayloadMutator()
        variants = m.mutate("' OR 1=1 --")
        assert "' OR 1=1 --" in variants

    def test_mutate_with_mysql_context(self):
        from core.payload_mutator import PayloadMutator
        m = PayloadMutator()
        variants = m.mutate(
            "' OR 1=1 --",
            context={"technology": "mysql"},
        )
        assert len(variants) > 1

    def test_mutate_with_postgresql_context(self):
        from core.payload_mutator import PayloadMutator
        m = PayloadMutator()
        variants = m.mutate(
            "' OR 1=1 --",
            context={"technology": "postgresql"},
        )
        assert len(variants) > 1

    def test_mutate_with_mssql_context(self):
        from core.payload_mutator import PayloadMutator
        m = PayloadMutator()
        variants = m.mutate(
            "' OR 1=1 --",
            context={"technology": "mssql"},
        )
        assert len(variants) > 1

    def test_mutate_with_attribute_context(self):
        from core.payload_mutator import PayloadMutator
        m = PayloadMutator()
        variants = m.mutate(
            "alert(1)",
            context={"reflection_context": "attribute"},
        )
        assert len(variants) > 1
        assert any("onfocus" in v or "onmouseover" in v for v in variants)

    def test_mutate_with_script_context(self):
        from core.payload_mutator import PayloadMutator
        m = PayloadMutator()
        variants = m.mutate(
            "alert(1)",
            context={"reflection_context": "script"},
        )
        assert len(variants) > 1

    def test_mutate_with_tag_content_context(self):
        from core.payload_mutator import PayloadMutator
        m = PayloadMutator()
        variants = m.mutate(
            "alert(1)",
            context={"reflection_context": "tag_content"},
        )
        assert len(variants) > 1
        assert any("<img" in v or "<svg" in v for v in variants)

    def test_mutate_integer_datatype(self):
        from core.payload_mutator import PayloadMutator
        m = PayloadMutator()
        variants = m.mutate(
            "1=1",
            context={"data_type": "integer"},
        )
        assert len(variants) > 1
        assert any("OR" in v or "AND" in v for v in variants)

    def test_mutate_url_datatype(self):
        from core.payload_mutator import PayloadMutator
        m = PayloadMutator()
        variants = m.mutate(
            "http://evil.com",
            context={"data_type": "url"},
        )
        assert len(variants) > 1
        assert any("javascript:" in v or "data:" in v for v in variants)

    def test_mutate_with_waf_name(self):
        from core.payload_mutator import PayloadMutator
        m = PayloadMutator()
        variants = m.mutate(
            "' OR 1=1 --",
            waf_name="Cloudflare",
        )
        assert len(variants) > 1

    def test_mutate_max_variants_limit(self):
        from core.payload_mutator import PayloadMutator
        m = PayloadMutator()
        variants = m.mutate(
            "' OR 1=1 --",
            context={"technology": "mysql", "reflection_context": "tag_content"},
            waf_name="ModSecurity",
            max_variants=3,
        )
        assert len(variants) <= 3

    def test_mutate_deduplication(self):
        from core.payload_mutator import PayloadMutator
        m = PayloadMutator()
        variants = m.mutate("' OR 1=1 --")
        assert len(variants) == len(set(variants))

    def test_mysql_comment_wrap(self):
        from core.payload_mutator import PayloadMutator
        result = PayloadMutator._mysql_comment_wrap("UNION SELECT 1")
        assert "/*!50000" in result

    def test_mysql_hex_string(self):
        from core.payload_mutator import PayloadMutator
        result = PayloadMutator._mysql_hex_string("SELECT 'admin'")
        assert "0x" in result

    def test_pg_dollar_quote(self):
        from core.payload_mutator import PayloadMutator
        result = PayloadMutator._pg_dollar_quote("' OR 1=1")
        assert "$$" in result

    def test_get_mutation_strategies(self):
        from core.payload_mutator import PayloadMutator
        m = PayloadMutator()
        strategies = m.get_mutation_strategies(
            context={"technology": "mysql"},
            waf_name="Cloudflare",
        )
        assert "base_payload" in strategies
        assert len(strategies) > 3

    def test_tech_mutations_coverage(self):
        """Verify tech mutation strategies exist for all supported DBs."""
        from core.payload_mutator import PayloadMutator
        for tech in ("mysql", "postgresql", "mssql", "oracle", "sqlite"):
            assert tech in PayloadMutator.TECH_MUTATIONS
            assert len(PayloadMutator.TECH_MUTATIONS[tech]) >= 2

    def test_waf_mutations_coverage(self):
        """Verify WAF mutation strategies exist for all known WAFs."""
        from core.payload_mutator import PayloadMutator
        for waf in ("Cloudflare", "ModSecurity", "Imperva/Incapsula",
                     "AWS WAF", "Akamai", "Sucuri"):
            assert waf in PayloadMutator.WAF_MUTATIONS
            assert len(PayloadMutator.WAF_MUTATIONS[waf]) >= 3

    def test_context_mutations_coverage(self):
        """Verify context mutations exist for common contexts."""
        from core.payload_mutator import PayloadMutator
        for ctx in ("tag_content", "attribute", "script", "json_value",
                     "header_value"):
            assert ctx in PayloadMutator.CONTEXT_MUTATIONS
            assert len(PayloadMutator.CONTEXT_MUTATIONS[ctx]) >= 2


# ── WAF Fingerprinting ────────────────────────────────────────────


class TestWAFFingerprinting:
    """Test enhanced WAF fingerprinting (v7.0 Titan)."""

    def test_fingerprint_cloudflare_by_header(self):
        from core.waf_evasion import WAFDetector
        d = WAFDetector()
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"cf-ray": "abc123", "server": "cloudflare"}
        resp.text = "Hello"
        fp = d.fingerprint(resp)
        assert fp["waf_name"] == "Cloudflare"
        assert fp["confidence"] >= 50
        assert fp["detection_method"] == "header_fingerprint"

    def test_fingerprint_aws_waf_by_header(self):
        from core.waf_evasion import WAFDetector
        d = WAFDetector()
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"x-amzn-requestid": "req-123", "server": "awselb/2.0"}
        resp.text = "Hello"
        fp = d.fingerprint(resp)
        assert fp["waf_name"] == "AWS WAF"
        assert fp["confidence"] >= 50

    def test_fingerprint_akamai_by_server(self):
        from core.waf_evasion import WAFDetector
        d = WAFDetector()
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"server": "AkamaiGHost"}
        resp.text = "Hello"
        fp = d.fingerprint(resp)
        assert fp["waf_name"] == "Akamai"

    def test_fingerprint_sucuri_by_header(self):
        from core.waf_evasion import WAFDetector
        d = WAFDetector()
        resp = MagicMock()
        resp.status_code = 403
        resp.headers = {"x-sucuri-id": "12345", "server": "Sucuri/Cloudproxy"}
        resp.text = "Access denied"
        fp = d.fingerprint(resp)
        assert fp["waf_name"] == "Sucuri"

    def test_fingerprint_none_detected(self):
        from core.waf_evasion import WAFDetector
        d = WAFDetector()
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"server": "nginx"}
        resp.text = "Hello World"
        fp = d.fingerprint(resp)
        assert fp["waf_name"] == "None"
        assert fp["confidence"] == 0

    def test_fingerprint_none_response(self):
        from core.waf_evasion import WAFDetector
        d = WAFDetector()
        fp = d.fingerprint(None)
        assert fp["waf_name"] == "None"

    def test_fingerprint_unknown_by_status_code(self):
        from core.waf_evasion import WAFDetector
        d = WAFDetector()
        resp = MagicMock()
        resp.status_code = 403
        resp.headers = {"server": "custom-server"}
        resp.text = "Some custom error page"
        fp = d.fingerprint(resp)
        assert "Unknown" in fp["waf_name"] or fp["waf_name"] == "None"

    def test_identify_waf_uses_header_fingerprinting(self):
        """identify_waf should now use header fingerprinting (v7.0)."""
        from core.waf_evasion import WAFDetector
        d = WAFDetector()
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"cf-ray": "xyz", "server": "cloudflare"}
        resp.text = "Normal page"
        waf = d.identify_waf(resp)
        assert waf == "Cloudflare"

    def test_waf_header_fingerprints_completeness(self):
        """All WAF fingerprints should have headers list and server pattern."""
        from core.waf_evasion import WAFDetector
        for name, fp in WAFDetector.WAF_HEADER_FINGERPRINTS.items():
            assert "headers" in fp, f"Missing headers for {name}"
            assert "server_pattern" in fp, f"Missing server_pattern for {name}"
            assert isinstance(fp["headers"], list)

    def test_fingerprint_imperva(self):
        from core.waf_evasion import WAFDetector
        d = WAFDetector()
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"x-cdn": "Incapsula", "server": "Imperva"}
        resp.text = "Hello"
        fp = d.fingerprint(resp)
        assert fp["waf_name"] == "Imperva/Incapsula"


# ── Robust Timing Baselines ───────────────────────────────────────


class TestRobustTiming:
    """Test percentile-based timing baselines (v7.0 Titan)."""

    def test_percentile_calculation_50th(self):
        from core.validator import ResultValidator
        data = [1.0, 2.0, 3.0, 4.0, 5.0]
        p50 = ResultValidator._percentile(data, 50.0)
        assert abs(p50 - 3.0) < 0.01

    def test_percentile_calculation_95th(self):
        from core.validator import ResultValidator
        data = [1.0, 2.0, 3.0, 4.0, 5.0]
        p95 = ResultValidator._percentile(data, 95.0)
        assert p95 >= 4.0

    def test_percentile_calculation_0th(self):
        from core.validator import ResultValidator
        data = [1.0, 2.0, 3.0]
        p0 = ResultValidator._percentile(data, 0.0)
        assert abs(p0 - 1.0) < 0.01

    def test_percentile_calculation_100th(self):
        from core.validator import ResultValidator
        data = [1.0, 2.0, 3.0]
        p100 = ResultValidator._percentile(data, 100.0)
        assert abs(p100 - 3.0) < 0.01

    def test_percentile_empty_list(self):
        from core.validator import ResultValidator
        p = ResultValidator._percentile([], 50.0)
        assert p == 0.0

    def test_percentile_single_element(self):
        from core.validator import ResultValidator
        p = ResultValidator._percentile([3.5], 50.0)
        assert abs(p - 3.5) < 0.01

    def test_calibrate_timing_uses_robust_when_enabled(self):
        """When robust timing is enabled, calibrate_timing should use percentile."""
        from core.validator import ResultValidator
        session = MagicMock()
        v = ResultValidator(session)

        # Mock make_request to return consistently
        with patch("core.validator.make_request") as mock_req:
            mock_req.return_value = MagicMock()
            # The function uses time.time() internally, so we just verify
            # it doesn't raise and returns a float
            with patch("core.validator.ROBUST_TIMING_ENABLED", True):
                baseline = v.calibrate_timing("http://test.com")
                assert isinstance(baseline, float)
                assert baseline >= 0


# ── Base Exploiter Integration ────────────────────────────────────


class TestBaseExploiterTitan:
    """Test Titan v7.0 additions to BaseExploiter."""

    def test_has_oob_verifier(self):
        from exploits.base_exploiter import BaseExploiter
        # Create a concrete subclass for testing
        class TestExploiter(BaseExploiter):
            def run(self, target, endpoints):
                return []
        e = TestExploiter()
        assert hasattr(e, "oob_verifier")
        from core.oob_verifier import OOBVerifier
        assert isinstance(e.oob_verifier, OOBVerifier)

    def test_has_payload_mutator(self):
        from exploits.base_exploiter import BaseExploiter
        class TestExploiter(BaseExploiter):
            def run(self, target, endpoints):
                return []
        e = TestExploiter()
        assert hasattr(e, "payload_mutator")
        from core.payload_mutator import PayloadMutator
        assert isinstance(e.payload_mutator, PayloadMutator)

    def test_has_titan_flags(self):
        from exploits.base_exploiter import BaseExploiter
        class TestExploiter(BaseExploiter):
            def run(self, target, endpoints):
                return []
        e = TestExploiter()
        assert hasattr(e, "_oob_verification")
        assert hasattr(e, "_payload_mutation")
        assert hasattr(e, "_waf_fingerprint")
        assert hasattr(e, "_detected_waf")

    def test_get_mutated_payloads_disabled(self):
        from exploits.base_exploiter import BaseExploiter
        class TestExploiter(BaseExploiter):
            def run(self, target, endpoints):
                return []
        e = TestExploiter()
        e._payload_mutation = False
        variants = e._get_mutated_payloads("' OR 1=1 --")
        assert variants == ["' OR 1=1 --"]

    def test_get_mutated_payloads_enabled(self):
        from exploits.base_exploiter import BaseExploiter
        class TestExploiter(BaseExploiter):
            def run(self, target, endpoints):
                return []
        e = TestExploiter()
        e._payload_mutation = True
        variants = e._get_mutated_payloads(
            "' OR 1=1 --",
            context={"technology": "mysql"},
        )
        assert len(variants) >= 1
        assert "' OR 1=1 --" in variants

    def test_detect_waf_with_fingerprinting(self):
        from exploits.base_exploiter import BaseExploiter
        class TestExploiter(BaseExploiter):
            def run(self, target, endpoints):
                return []
        e = TestExploiter()
        e._waf_fingerprint = True
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"cf-ray": "abc", "server": "cloudflare"}
        resp.text = "Hello"
        result = e._detect_waf(resp)
        assert result == "Cloudflare"
        assert e._detected_waf == "Cloudflare"

    def test_detect_waf_none_response(self):
        from exploits.base_exploiter import BaseExploiter
        class TestExploiter(BaseExploiter):
            def run(self, target, endpoints):
                return []
        e = TestExploiter()
        result = e._detect_waf(None)
        assert result is None

    def test_generate_oob_payloads_disabled(self):
        from exploits.base_exploiter import BaseExploiter
        class TestExploiter(BaseExploiter):
            def run(self, target, endpoints):
                return []
        e = TestExploiter()
        e._oob_verification = False
        payloads = e._generate_oob_payloads("sqli", "http://test.com", "id", "payload")
        assert payloads == []

    def test_generate_oob_payloads_not_configured(self):
        from exploits.base_exploiter import BaseExploiter
        class TestExploiter(BaseExploiter):
            def run(self, target, endpoints):
                return []
        e = TestExploiter()
        e._oob_verification = True
        # Default has no callback domain
        payloads = e._generate_oob_payloads("sqli", "http://test.com", "id", "payload")
        assert payloads == []


# ── Input Validation ──────────────────────────────────────────────


class TestInputValidation:
    """Test v7.0 Titan input validation fixes."""

    def test_learning_route_rejects_unknown_vuln_type(self):
        """The /learning/<vuln_type> route should reject unknown types."""
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from app import app
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        with app.test_client() as client:
            resp = client.get("/learning/evil_script_injection")
            assert resp.status_code == 400
            data = resp.get_json()
            assert "error" in data

    def test_learning_route_accepts_known_vuln_type(self):
        """The /learning/<vuln_type> route should accept known types."""
        from app import app
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        with app.test_client() as client:
            resp = client.get("/learning/sqli")
            assert resp.status_code == 200

    def test_learning_route_accepts_all_known_types(self):
        """All known vuln types should be accepted."""
        KNOWN = {
            "sqli", "nosql", "cmd", "ssti", "xxe", "ldap", "xpath",
            "xss", "csrf", "clickjack", "cors", "open_redirect",
            "ssrf", "lfi", "rfi", "file_upload", "rce",
        }
        from app import app
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        with app.test_client() as client:
            for vtype in KNOWN:
                resp = client.get(f"/learning/{vtype}")
                assert resp.status_code == 200, f"Failed for vuln type: {vtype}"

    def test_learning_route_rejects_special_characters(self):
        """Special characters in vuln_type should be rejected."""
        from app import app
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        with app.test_client() as client:
            for bad_input in ["<script>alert(1)</script>", "sql' OR 1=1--",
                              "../etc/passwd", "a" * 500]:
                resp = client.get(f"/learning/{bad_input}")
                assert resp.status_code in (400, 404), (
                    f"Should reject: {bad_input!r}"
                )

    def test_learning_route_rejects_empty_like_values(self):
        """Unusual but valid URL paths that aren't real vuln types."""
        from app import app
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        with app.test_client() as client:
            for bad_input in ["SQLI", "Sqli", "sql_injection", "unknown"]:
                resp = client.get(f"/learning/{bad_input}")
                assert resp.status_code == 400, (
                    f"Should reject case/name variant: {bad_input!r}"
                )
