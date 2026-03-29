"""Tests for VenomStrike v10.0 Phoenix Edition features.

Covers:
- Phoenix config settings & depth preset
- Smart Parameter Deduplicator (semantic grouping, archetypes)
- Context-Aware Vulnerability Validator (tech detection, FP filtering)
- Intelligent Payload Minimizer (coverage-based selection)
- Vulnerability Impact Analyzer (exploitability, priority)
- Adaptive Scan Profiler (response profiling, recommendations)
- Enhanced BaseExploiter integration of Phoenix modules
- Engine integration of Phoenix depth preset
"""
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Config: Phoenix settings ─────────────────────────────────────


class TestPhoenixConfig:
    """Verify Phoenix v10.0 config additions."""

    def test_version_is_10(self):
        import config
        assert config.VERSION == "10.0.0"

    def test_codename_is_phoenix(self):
        import config
        assert config.CODENAME == "Phoenix"

    def test_phoenix_depth_preset_exists(self):
        import config
        assert "phoenix" in config.DEPTH_PRESETS

    def test_phoenix_depth_is_valid(self):
        import config
        assert "phoenix" in config._VALID_DEPTHS

    def test_phoenix_preset_has_required_keys(self):
        import config
        preset = config.DEPTH_PRESETS["phoenix"]
        for key in ("crawl_depth", "max_crawl_pages", "dir_brute_limit",
                     "api_brute_limit", "payload_limit", "validation_attempts",
                     "min_confidence"):
            assert key in preset, f"Missing key: {key}"

    def test_phoenix_preset_deeper_than_chimera(self):
        import config
        p = config.DEPTH_PRESETS["phoenix"]
        c = config.DEPTH_PRESETS["chimera"]
        assert p["crawl_depth"] > c["crawl_depth"]
        assert p["max_crawl_pages"] > c["max_crawl_pages"]
        assert p["validation_attempts"] > c["validation_attempts"]

    def test_phoenix_preset_inherits_chimera_flags(self):
        import config
        preset = config.DEPTH_PRESETS["phoenix"]
        assert preset.get("adaptive_rate_limiting") is True
        assert preset.get("vulnerability_correlation") is True
        assert preset.get("scan_optimization") is True
        assert preset.get("sarif_output") is True
        assert preset.get("parameter_tampering") is True

    def test_phoenix_preset_inherits_hydra_flags(self):
        import config
        preset = config.DEPTH_PRESETS["phoenix"]
        assert preset.get("smart_payload_selection") is True
        assert preset.get("attack_chain_correlation") is True
        assert preset.get("bayesian_scoring") is True
        assert preset.get("response_intelligence") is True
        assert preset.get("adaptive_exploitation") is True

    def test_phoenix_preset_inherits_titan_flags(self):
        import config
        preset = config.DEPTH_PRESETS["phoenix"]
        assert preset.get("oob_verification") is True
        assert preset.get("payload_mutation") is True
        assert preset.get("robust_timing") is True
        assert preset.get("waf_fingerprinting") is True

    def test_phoenix_preset_has_new_flags(self):
        import config
        preset = config.DEPTH_PRESETS["phoenix"]
        assert preset.get("param_deduplication") is True
        assert preset.get("context_validation") is True
        assert preset.get("payload_minimization") is True
        assert preset.get("impact_analysis") is True
        assert preset.get("scan_profiling") is True

    def test_phoenix_config_settings_exist(self):
        import config
        assert hasattr(config, "PARAM_DEDUP_ENABLED")
        assert hasattr(config, "PARAM_DEDUP_SIMILARITY_THRESHOLD")
        assert hasattr(config, "PARAM_DEDUP_MAX_PER_TYPE")
        assert hasattr(config, "CONTEXT_VALIDATION_ENABLED")
        assert hasattr(config, "CONTEXT_VALIDATION_BOOST")
        assert hasattr(config, "CONTEXT_VALIDATION_PENALTY")
        assert hasattr(config, "PAYLOAD_MINIMIZER_ENABLED")
        assert hasattr(config, "PAYLOAD_MINIMIZER_MAX_RATIO")
        assert hasattr(config, "PAYLOAD_MINIMIZER_MIN_PAYLOADS")
        assert hasattr(config, "IMPACT_ANALYSIS_ENABLED")
        assert hasattr(config, "SCAN_PROFILER_ENABLED")
        assert hasattr(config, "SCAN_PROFILER_WINDOW_SIZE")
        assert hasattr(config, "SCAN_PROFILER_ERROR_THRESHOLD")
        assert hasattr(config, "SCAN_PROFILER_LATENCY_MULTIPLIER")

    def test_user_agent_updated(self):
        import config
        assert "10.0-Phoenix" in config.DEFAULT_USER_AGENT

    def test_nine_valid_depths(self):
        import config
        assert len(config._VALID_DEPTHS) == 9
        assert "phoenix" in config._VALID_DEPTHS


# ── Smart Parameter Deduplicator ─────────────────────────────────


class TestSmartParamDeduplicator:
    """Test the smart parameter deduplication engine."""

    def test_deduplicate_params_basic(self):
        from core.param_deduplicator import SmartParamDeduplicator
        dedup = SmartParamDeduplicator(max_per_type=2)
        params = ["id", "user_id", "account_id", "pk", "ref",
                  "q", "query", "search", "keyword"]
        with patch("core.param_deduplicator.PARAM_DEDUP_ENABLED", True):
            result = dedup.deduplicate_params(params)
        assert len(result) < len(params)
        assert len(result) > 0

    def test_deduplicate_params_disabled(self):
        from core.param_deduplicator import SmartParamDeduplicator
        dedup = SmartParamDeduplicator()
        params = ["id", "user_id", "account_id", "pk", "ref"]
        with patch("core.param_deduplicator.PARAM_DEDUP_ENABLED", False):
            result = dedup.deduplicate_params(params)
        assert result == params

    def test_deduplicate_params_empty(self):
        from core.param_deduplicator import SmartParamDeduplicator
        dedup = SmartParamDeduplicator()
        with patch("core.param_deduplicator.PARAM_DEDUP_ENABLED", True):
            result = dedup.deduplicate_params([])
        assert result == []

    def test_normalize_param_name(self):
        from core.param_deduplicator import _normalize_param_name
        assert _normalize_param_name("userId") == "user_id"
        assert _normalize_param_name("product-id") == "product_id"
        assert _normalize_param_name("Item_ID") == "item_id"
        assert _normalize_param_name("page2") == "page"

    def test_classify_param_identifiers(self):
        from core.param_deduplicator import _classify_param
        assert _classify_param("id") == "identifier"
        assert _classify_param("user_id") == "identifier"
        assert _classify_param("pk") == "identifier"

    def test_classify_param_search(self):
        from core.param_deduplicator import _classify_param
        assert _classify_param("q") == "search"
        assert _classify_param("query") == "search"
        assert _classify_param("search") == "search"
        assert _classify_param("keyword") == "search"

    def test_classify_param_unknown(self):
        from core.param_deduplicator import _classify_param
        assert _classify_param("xyzzy_foobar") == "unknown"
        assert _classify_param("randomthing") == "unknown"

    def test_similarity_score_identical(self):
        from core.param_deduplicator import _similarity_score
        assert _similarity_score("user_id", "user_id") == 1.0

    def test_similarity_score_different(self):
        from core.param_deduplicator import _similarity_score
        score = _similarity_score("user_id", "xyzzy_foobar")
        assert score < 0.5

    def test_deduplicate_endpoints(self):
        from core.param_deduplicator import SmartParamDeduplicator
        dedup = SmartParamDeduplicator(max_per_type=2)
        endpoints = [
            {"url": "http://t.com/api", "params": ["id", "user_id", "pk", "ref", "index"]},
            {"url": "http://t.com/search", "params": ["q", "query", "search", "keyword"]},
        ]
        with patch("core.param_deduplicator.PARAM_DEDUP_ENABLED", True):
            result = dedup.deduplicate_endpoints(endpoints)
        assert len(result) == 2
        assert len(result[0]["params"]) <= len(endpoints[0]["params"])
        assert len(result[1]["params"]) <= len(endpoints[1]["params"])

    def test_get_stats(self):
        from core.param_deduplicator import SmartParamDeduplicator
        dedup = SmartParamDeduplicator(max_per_type=2)
        with patch("core.param_deduplicator.PARAM_DEDUP_ENABLED", True):
            dedup.deduplicate_params(["id", "user_id", "pk", "ref", "q", "query"])
        stats = dedup.get_stats()
        assert "total_before" in stats
        assert "total_after" in stats
        assert "reduction_percent" in stats
        assert "archetype_counts" in stats

    def test_select_representatives_max_per_type(self):
        from core.param_deduplicator import SmartParamDeduplicator
        dedup = SmartParamDeduplicator(max_per_type=2)
        group = ["id", "user_id", "account_id", "pk", "ref", "index", "num"]
        selected = dedup._select_representatives(group)
        assert len(selected) <= 2

    def test_similarity_score_camel_vs_snake(self):
        from core.param_deduplicator import _similarity_score
        score = _similarity_score("userId", "user_id")
        assert score == 1.0

    def test_classify_param_file_path(self):
        from core.param_deduplicator import _classify_param
        assert _classify_param("file") == "file_path"
        assert _classify_param("path") == "file_path"

    def test_classify_param_url(self):
        from core.param_deduplicator import _classify_param
        assert _classify_param("url") == "url"
        assert _classify_param("redirect") == "url"
        assert _classify_param("callback") == "url"

    def test_classify_param_command(self):
        from core.param_deduplicator import _classify_param
        assert _classify_param("cmd") == "command"
        assert _classify_param("host") == "command"

    def test_deduplicate_endpoints_dict_params(self):
        from core.param_deduplicator import SmartParamDeduplicator
        dedup = SmartParamDeduplicator(max_per_type=2)
        endpoints = [
            {"url": "http://t.com/api", "params": [
                {"name": "id"}, {"name": "user_id"}, {"name": "pk"},
            ]},
        ]
        with patch("core.param_deduplicator.PARAM_DEDUP_ENABLED", True):
            result = dedup.deduplicate_endpoints(endpoints)
        assert len(result[0]["params"]) <= 3

    def test_deduplicate_endpoints_disabled(self):
        from core.param_deduplicator import SmartParamDeduplicator
        dedup = SmartParamDeduplicator()
        endpoints = [{"url": "http://t.com/api", "params": ["id", "user_id"]}]
        with patch("core.param_deduplicator.PARAM_DEDUP_ENABLED", False):
            result = dedup.deduplicate_endpoints(endpoints)
        assert result == endpoints


# ── Context Validator ────────────────────────────────────────────


class TestContextValidator:
    """Test context-aware vulnerability validation."""

    def test_detect_technology_django(self):
        from core.context_validator import ContextValidator
        cv = ContextValidator()
        tech = cv.detect_technology(body="<input name='csrfmiddlewaretoken' value='abc'>")
        assert tech == "django"

    def test_detect_technology_rails(self):
        from core.context_validator import ContextValidator
        cv = ContextValidator()
        tech = cv.detect_technology(body="action_dispatch cookies set for rails app")
        assert tech == "rails"

    def test_detect_technology_express(self):
        from core.context_validator import ContextValidator
        cv = ContextValidator()
        tech = cv.detect_technology(headers={"X-Powered-By": "Express"})
        assert tech == "express"

    def test_detect_technology_none(self):
        from core.context_validator import ContextValidator
        cv = ContextValidator()
        tech = cv.detect_technology(body="<html><body>Hello</body></html>")
        assert tech is None

    def test_validate_finding_no_change(self):
        from core.context_validator import ContextValidator
        cv = ContextValidator()
        finding = {"vuln_type": "sqli", "confidence": 80}
        with patch("core.context_validator.CONTEXT_VALIDATION_ENABLED", True):
            result = cv.validate_finding(finding, technology=None, response_body="OK")
        assert result["confidence"] == 80
        assert result["context_validation"]["adjustment"] == 0

    def test_validate_finding_fp_django_csrf(self):
        from core.context_validator import ContextValidator
        cv = ContextValidator()
        finding = {"vuln_type": "xss", "confidence": 80}
        with patch("core.context_validator.CONTEXT_VALIDATION_ENABLED", True):
            result = cv.validate_finding(
                finding,
                technology="django",
                response_body="csrfmiddlewaretoken=abc123",
            )
        assert result["context_validation"]["is_false_positive"] is True
        assert result["context_validation"]["adjustment"] < 0
        assert result["confidence"] < 80

    def test_validate_finding_tech_boost(self):
        from core.context_validator import ContextValidator
        cv = ContextValidator()
        finding = {"vuln_type": "sqli", "confidence": 60}
        with patch("core.context_validator.CONTEXT_VALIDATION_ENABLED", True):
            result = cv.validate_finding(
                finding,
                technology="django",
                response_body="ProgrammingError at /api/users",
            )
        assert result["context_validation"]["adjustment"] > 0
        assert result["confidence"] > 60

    def test_validate_findings_list(self):
        from core.context_validator import ContextValidator
        cv = ContextValidator()
        findings = [
            {"vuln_type": "sqli", "confidence": 80},
            {"vuln_type": "xss", "confidence": 70},
        ]
        with patch("core.context_validator.CONTEXT_VALIDATION_ENABLED", True):
            results = cv.validate_findings(findings)
        assert len(results) == 2
        assert all("context_validation" in f for f in results)

    def test_get_stats(self):
        from core.context_validator import ContextValidator
        cv = ContextValidator()
        stats = cv.get_stats()
        assert "validated" in stats
        assert "adjusted" in stats
        assert "rejected_as_fp" in stats
        assert "detected_technology" in stats

    def test_validate_finding_disabled(self):
        from core.context_validator import ContextValidator
        cv = ContextValidator()
        finding = {"vuln_type": "sqli", "confidence": 80}
        with patch("core.context_validator.CONTEXT_VALIDATION_ENABLED", False):
            result = cv.validate_finding(finding)
        assert result == finding

    def test_validate_findings_disabled(self):
        from core.context_validator import ContextValidator
        cv = ContextValidator()
        findings = [{"vuln_type": "sqli", "confidence": 80}]
        with patch("core.context_validator.CONTEXT_VALIDATION_ENABLED", False):
            results = cv.validate_findings(findings)
        assert results == findings

    def test_detect_technology_flask(self):
        from core.context_validator import ContextValidator
        cv = ContextValidator()
        tech = cv.detect_technology(body="Werkzeug debugger active")
        assert tech == "flask"

    def test_detect_technology_wordpress(self):
        from core.context_validator import ContextValidator
        cv = ContextValidator()
        tech = cv.detect_technology(body='<link href="/wp-content/themes/style.css">')
        assert tech == "wordpress"

    def test_security_middleware_penalty(self):
        from core.context_validator import ContextValidator
        cv = ContextValidator()
        finding = {"vuln_type": "sqli", "confidence": 80}
        with patch("core.context_validator.CONTEXT_VALIDATION_ENABLED", True):
            result = cv.validate_finding(
                finding, response_body="Access Denied — request blocked by WAF"
            )
        assert result["context_validation"]["adjustment"] < 0

    def test_validate_finding_rails_csrf_fp(self):
        from core.context_validator import ContextValidator
        cv = ContextValidator()
        finding = {"vuln_type": "xss", "confidence": 75}
        with patch("core.context_validator.CONTEXT_VALIDATION_ENABLED", True):
            result = cv.validate_finding(
                finding,
                technology="rails",
                response_body='<input name="authenticity_token" value="xyz">',
            )
        assert result["context_validation"]["is_false_positive"] is True


# ── Payload Minimizer ────────────────────────────────────────────


class TestPayloadMinimizer:
    """Test intelligent payload minimization."""

    def test_minimize_basic(self):
        from core.payload_minimizer import PayloadMinimizer
        pm = PayloadMinimizer(min_payloads=3)
        payloads = [
            "' OR 1=1--",
            "' OR 2=2--",
            "' OR 3=3--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 4,5,6--",
            "<script>alert(1)</script>",
            "<script>alert(2)</script>",
            "<img onerror=alert(1) src=x>",
            "<svg onload=alert(1)>",
            "| ls",
            "; cat /etc/passwd",
            "{{7*7}}",
            "${7*7}",
            "../../etc/passwd",
            "..\\..\\etc\\passwd",
        ]
        with patch("core.payload_minimizer.PAYLOAD_MINIMIZER_ENABLED", True):
            result = pm.minimize(payloads)
        assert len(result) < len(payloads)
        assert len(result) >= 3

    def test_minimize_disabled(self):
        from core.payload_minimizer import PayloadMinimizer
        pm = PayloadMinimizer()
        payloads = ["' OR 1=1--", "<script>alert(1)</script>"]
        with patch("core.payload_minimizer.PAYLOAD_MINIMIZER_ENABLED", False):
            result = pm.minimize(payloads)
        assert result == payloads

    def test_minimize_empty(self):
        from core.payload_minimizer import PayloadMinimizer
        pm = PayloadMinimizer()
        with patch("core.payload_minimizer.PAYLOAD_MINIMIZER_ENABLED", True):
            result = pm.minimize([])
        assert result == []

    def test_structural_fingerprint(self):
        from core.payload_minimizer import _structural_fingerprint
        fp1 = _structural_fingerprint("' OR 1=1--")
        fp2 = _structural_fingerprint("' OR 2=2--")
        assert fp1 == fp2

    def test_classify_payload_sqli(self):
        from core.payload_minimizer import _classify_payload
        cats = _classify_payload("' UNION SELECT 1,2,3--")
        assert "sqli_union" in cats

    def test_classify_payload_xss(self):
        from core.payload_minimizer import _classify_payload
        cats = _classify_payload("<script>alert(1)</script>")
        assert "xss_script" in cats

    def test_coverage_maintained(self):
        from core.payload_minimizer import PayloadMinimizer, _classify_payload
        pm = PayloadMinimizer(min_payloads=2)
        payloads = [
            "' OR 1=1--",
            "' UNION SELECT 1,2,3--",
            "<script>alert(1)</script>",
            "| ls",
            "{{7*7}}",
        ]
        with patch("core.payload_minimizer.PAYLOAD_MINIMIZER_ENABLED", True):
            result = pm.minimize(payloads)
        # Collect all categories from input and output
        input_cats = set()
        for p in payloads:
            input_cats |= _classify_payload(p)
        output_cats = set()
        for p in result:
            output_cats |= _classify_payload(p)
        assert input_cats == output_cats

    def test_get_stats(self):
        from core.payload_minimizer import PayloadMinimizer
        pm = PayloadMinimizer(min_payloads=2)
        with patch("core.payload_minimizer.PAYLOAD_MINIMIZER_ENABLED", True):
            pm.minimize(["' OR 1=1--", "<script>alert(1)</script>", "| ls"])
        stats = pm.get_stats()
        assert "total_before" in stats
        assert "total_after" in stats
        assert "reduction_percent" in stats

    def test_min_payloads_respected(self):
        from core.payload_minimizer import PayloadMinimizer
        pm = PayloadMinimizer(min_payloads=5)
        payloads = [
            "' OR 1=1--",
            "' UNION SELECT 1,2,3--",
            "<script>alert(1)</script>",
            "<img onerror=alert(1) src=x>",
            "<svg onload=alert(1)>",
            "| ls -la",
            "; cat /etc/passwd",
            "{{7*7}}",
            "../../etc/passwd",
            "127.0.0.1",
        ]
        with patch("core.payload_minimizer.PAYLOAD_MINIMIZER_ENABLED", True):
            result = pm.minimize(payloads)
        assert len(result) >= 5

    def test_classify_payload_cmd(self):
        from core.payload_minimizer import _classify_payload
        cats = _classify_payload("| ls -la")
        assert "cmd_pipe" in cats

    def test_classify_payload_ssti(self):
        from core.payload_minimizer import _classify_payload
        cats = _classify_payload("{{7*7}}")
        assert "ssti_jinja" in cats

    def test_classify_payload_traversal(self):
        from core.payload_minimizer import _classify_payload
        cats = _classify_payload("../../etc/passwd")
        assert "traversal_unix" in cats

    def test_structural_fingerprint_different(self):
        from core.payload_minimizer import _structural_fingerprint
        fp1 = _structural_fingerprint("' OR 1=1--")
        fp2 = _structural_fingerprint("<script>alert(1)</script>")
        assert fp1 != fp2


# ── Impact Analyzer ──────────────────────────────────────────────


class TestImpactAnalyzer:
    """Test vulnerability impact analysis."""

    def test_analyze_finding_basic(self):
        from core.impact_analyzer import ImpactAnalyzer
        ia = ImpactAnalyzer()
        finding = {"vuln_type": "SQL Injection", "url": "http://t.com/api", "param": "id", "confidence": 90}
        with patch("core.impact_analyzer.IMPACT_ANALYSIS_ENABLED", True):
            result = ia.analyze_finding(finding)
        assert "impact_analysis" in result
        assert "exploitability" in result["impact_analysis"]
        assert "remediation_priority" in result["impact_analysis"]
        assert "impact_score" in result["impact_analysis"]

    def test_analyze_finding_disabled(self):
        from core.impact_analyzer import ImpactAnalyzer
        ia = ImpactAnalyzer()
        finding = {"vuln_type": "SQL Injection", "url": "http://t.com", "param": "id", "confidence": 90}
        with patch("core.impact_analyzer.IMPACT_ANALYSIS_ENABLED", False):
            result = ia.analyze_finding(finding)
        assert result == finding

    def test_exploitability_sqli(self):
        from core.impact_analyzer import ImpactAnalyzer
        ia = ImpactAnalyzer()
        finding = {"vuln_type": "SQL Injection", "url": "http://t.com", "param": "id", "confidence": 80}
        with patch("core.impact_analyzer.IMPACT_ANALYSIS_ENABLED", True):
            result = ia.analyze_finding(finding)
        assert result["impact_analysis"]["exploitability"] >= 80

    def test_exploitability_clickjacking(self):
        from core.impact_analyzer import ImpactAnalyzer
        ia = ImpactAnalyzer()
        finding = {"vuln_type": "Clickjacking", "url": "http://t.com", "param": "", "confidence": 50}
        with patch("core.impact_analyzer.IMPACT_ANALYSIS_ENABLED", True):
            result = ia.analyze_finding(finding)
        assert result["impact_analysis"]["exploitability"] < 80

    def test_data_sensitivity_password(self):
        from core.impact_analyzer import ImpactAnalyzer
        ia = ImpactAnalyzer()
        finding = {"vuln_type": "SQL Injection", "url": "http://t.com/auth", "param": "password", "confidence": 90}
        with patch("core.impact_analyzer.IMPACT_ANALYSIS_ENABLED", True):
            result = ia.analyze_finding(finding)
        assert result["impact_analysis"]["data_sensitivity"] == "critical"
        assert result["impact_analysis"]["data_sensitivity_score"] == 100

    def test_data_sensitivity_search(self):
        from core.impact_analyzer import ImpactAnalyzer
        ia = ImpactAnalyzer()
        finding = {"vuln_type": "XSS (Reflected)", "url": "http://t.com/search", "param": "query", "confidence": 60}
        with patch("core.impact_analyzer.IMPACT_ANALYSIS_ENABLED", True):
            result = ia.analyze_finding(finding)
        assert result["impact_analysis"]["data_sensitivity"] == "low"
        assert result["impact_analysis"]["data_sensitivity_score"] <= 30

    def test_complexity_waf_penalty(self):
        from core.impact_analyzer import ImpactAnalyzer
        ia = ImpactAnalyzer()
        finding = {"vuln_type": "SQL Injection", "url": "http://t.com", "param": "id", "confidence": 80}
        with patch("core.impact_analyzer.IMPACT_ANALYSIS_ENABLED", True):
            result_no_waf = ia.analyze_finding(finding, waf_detected=False)
            result_waf = ia.analyze_finding(finding, waf_detected=True)
        assert result_waf["impact_analysis"]["exploitability"] < result_no_waf["impact_analysis"]["exploitability"]

    def test_priority_labels(self):
        from core.impact_analyzer import ImpactAnalyzer
        ia = ImpactAnalyzer()
        high_finding = {"vuln_type": "SQL Injection", "url": "http://t.com/auth", "param": "password", "confidence": 95}
        low_finding = {"vuln_type": "Clickjacking", "url": "http://t.com/page", "param": "debug", "confidence": 20}
        with patch("core.impact_analyzer.IMPACT_ANALYSIS_ENABLED", True):
            high_result = ia.analyze_finding(high_finding)
            low_result = ia.analyze_finding(low_finding)
        assert high_result["impact_analysis"]["remediation_priority"] == "P0-Critical"
        assert low_result["impact_analysis"]["remediation_priority"] in ("P3-Low", "P2-Medium", "P4-Info")

    def test_analyze_findings_sorted(self):
        from core.impact_analyzer import ImpactAnalyzer
        ia = ImpactAnalyzer()
        findings = [
            {"vuln_type": "Clickjacking", "url": "http://t.com", "param": "", "confidence": 30},
            {"vuln_type": "SQL Injection", "url": "http://t.com/auth", "param": "password", "confidence": 95},
            {"vuln_type": "Open Redirect", "url": "http://t.com", "param": "next", "confidence": 50},
        ]
        with patch("core.impact_analyzer.IMPACT_ANALYSIS_ENABLED", True):
            results = ia.analyze_findings(findings)
        scores = [r["impact_analysis"]["impact_score"] for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_get_stats(self):
        from core.impact_analyzer import ImpactAnalyzer
        ia = ImpactAnalyzer()
        with patch("core.impact_analyzer.IMPACT_ANALYSIS_ENABLED", True):
            ia.analyze_finding({"vuln_type": "XSS (Reflected)", "url": "http://t.com", "param": "q", "confidence": 70})
        stats = ia.get_stats()
        assert "analyzed_count" in stats
        assert stats["analyzed_count"] == 1

    def test_analyze_findings_disabled(self):
        from core.impact_analyzer import ImpactAnalyzer
        ia = ImpactAnalyzer()
        findings = [{"vuln_type": "sqli", "confidence": 80}]
        with patch("core.impact_analyzer.IMPACT_ANALYSIS_ENABLED", False):
            results = ia.analyze_findings(findings)
        assert results == findings

    def test_auth_required_reduces_exploitability(self):
        from core.impact_analyzer import ImpactAnalyzer
        ia = ImpactAnalyzer()
        finding = {"vuln_type": "SQL Injection", "url": "http://t.com", "param": "id", "confidence": 80}
        with patch("core.impact_analyzer.IMPACT_ANALYSIS_ENABLED", True):
            result_no_auth = ia.analyze_finding(finding, auth_required=False)
            result_auth = ia.analyze_finding(finding, auth_required=True)
        assert result_auth["impact_analysis"]["exploitability"] < result_no_auth["impact_analysis"]["exploitability"]

    def test_blind_sqli_lower_exploitability(self):
        from core.impact_analyzer import ImpactAnalyzer
        ia = ImpactAnalyzer()
        error_finding = {"vuln_type": "SQL Injection (Error-Based)", "url": "http://t.com", "param": "id", "confidence": 80}
        blind_finding = {"vuln_type": "SQL Injection (Boolean Blind)", "url": "http://t.com", "param": "id", "confidence": 80}
        with patch("core.impact_analyzer.IMPACT_ANALYSIS_ENABLED", True):
            error_result = ia.analyze_finding(error_finding)
            blind_result = ia.analyze_finding(blind_finding)
        assert blind_result["impact_analysis"]["exploitability"] < error_result["impact_analysis"]["exploitability"]

    def test_priority_rank_ordering(self):
        from core.impact_analyzer import ImpactAnalyzer
        ia = ImpactAnalyzer()
        assert ia._priority_rank("P0-Critical") < ia._priority_rank("P1-High")
        assert ia._priority_rank("P1-High") < ia._priority_rank("P2-Medium")
        assert ia._priority_rank("P2-Medium") < ia._priority_rank("P3-Low")
        assert ia._priority_rank("P3-Low") < ia._priority_rank("P4-Info")


# ── Scan Profiler ────────────────────────────────────────────────


class TestScanProfiler:
    """Test adaptive scan profiling."""

    def test_record_response_basic(self):
        from core.scan_profiler import ScanProfiler
        sp = ScanProfiler()
        with patch("core.scan_profiler.SCAN_PROFILER_ENABLED", True):
            sp.record_response("/api/users", 0.15, 200)
        stats = sp.get_global_stats()
        assert stats["total_requests"] == 1

    def test_record_response_disabled(self):
        from core.scan_profiler import ScanProfiler
        sp = ScanProfiler()
        with patch("core.scan_profiler.SCAN_PROFILER_ENABLED", False):
            sp.record_response("/api/users", 0.15, 200)
        stats = sp.get_global_stats()
        assert stats["total_requests"] == 0

    def test_record_finding(self):
        from core.scan_profiler import ScanProfiler
        sp = ScanProfiler()
        with patch("core.scan_profiler.SCAN_PROFILER_ENABLED", True):
            sp.record_response("/api/users", 0.15, 200)
            sp.record_finding("/api/users")
        prioritized = sp.get_prioritised_endpoints()
        assert len(prioritized) == 1
        assert prioritized[0]["has_findings"] is True

    def test_get_recommendation_no_data(self):
        from core.scan_profiler import ScanProfiler
        sp = ScanProfiler()
        with patch("core.scan_profiler.SCAN_PROFILER_ENABLED", True):
            rec = sp.get_recommendation("/unknown")
        assert rec["should_scan"] is True
        assert rec["depth_modifier"] == 0

    def test_get_recommendation_high_errors(self):
        from core.scan_profiler import ScanProfiler
        sp = ScanProfiler(error_threshold=0.3)
        with patch("core.scan_profiler.SCAN_PROFILER_ENABLED", True):
            for _ in range(10):
                sp.record_response("/api/admin", 0.5, 500)
            rec = sp.get_recommendation("/api/admin")
        assert rec["depth_modifier"] < 0

    def test_get_recommendation_findings(self):
        from core.scan_profiler import ScanProfiler
        sp = ScanProfiler()
        with patch("core.scan_profiler.SCAN_PROFILER_ENABLED", True):
            sp.record_response("/api/vuln", 0.1, 200)
            sp.record_finding("/api/vuln")
            rec = sp.get_recommendation("/api/vuln")
        assert rec["depth_modifier"] > 0
        assert rec["should_scan"] is True

    def test_get_prioritised_endpoints(self):
        from core.scan_profiler import ScanProfiler
        sp = ScanProfiler()
        with patch("core.scan_profiler.SCAN_PROFILER_ENABLED", True):
            sp.record_response("/api/normal", 0.1, 200)
            sp.record_response("/api/vuln", 0.1, 200)
            sp.record_finding("/api/vuln")
        prioritized = sp.get_prioritised_endpoints()
        assert len(prioritized) == 2
        assert prioritized[0]["has_findings"] is True

    def test_endpoint_profile_stats(self):
        from core.scan_profiler import EndpointProfile
        ep = EndpointProfile("/api/test")
        ep.record(0.1, 200)
        ep.record(0.2, 200)
        ep.record(0.3, 200)
        ep.record(0.5, 500)
        d = ep.to_dict()
        assert "avg_response_time" in d
        assert "p95_response_time" in d
        assert "error_rate" in d
        assert d["observations"] == 4
        assert d["error_rate"] > 0

    def test_global_stats(self):
        from core.scan_profiler import ScanProfiler
        sp = ScanProfiler()
        with patch("core.scan_profiler.SCAN_PROFILER_ENABLED", True):
            sp.record_response("/a", 0.1, 200)
            sp.record_response("/b", 0.2, 200)
        stats = sp.get_global_stats()
        assert "total_requests" in stats
        assert "avg_response_time" in stats
        assert "global_error_rate" in stats
        assert "target_stressed" in stats
        assert "endpoints_profiled" in stats
        assert stats["total_requests"] == 2
        assert stats["endpoints_profiled"] == 2

    def test_target_stress_detection(self):
        from core.scan_profiler import ScanProfiler
        sp = ScanProfiler(error_threshold=0.2)
        with patch("core.scan_profiler.SCAN_PROFILER_ENABLED", True):
            # Send enough error responses to trigger stress
            for _ in range(15):
                sp.record_response("/api/target", 2.0, 500)
        assert sp.is_target_stressed() is True

    def test_endpoint_profile_empty(self):
        from core.scan_profiler import EndpointProfile
        ep = EndpointProfile("/empty")
        assert ep.avg_response_time == 0.0
        assert ep.p95_response_time == 0.0
        assert ep.error_rate == 0.0

    def test_record_finding_disabled(self):
        from core.scan_profiler import ScanProfiler
        sp = ScanProfiler()
        with patch("core.scan_profiler.SCAN_PROFILER_ENABLED", False):
            sp.record_finding("/api/test")
        assert sp.get_prioritised_endpoints() == []

    def test_get_recommendation_disabled(self):
        from core.scan_profiler import ScanProfiler
        sp = ScanProfiler()
        with patch("core.scan_profiler.SCAN_PROFILER_ENABLED", False):
            rec = sp.get_recommendation("/api/test")
        assert rec["should_scan"] is True
        assert rec["reason"] == "Profiling disabled"

    def test_multiple_findings_boost(self):
        from core.scan_profiler import ScanProfiler
        sp = ScanProfiler()
        with patch("core.scan_profiler.SCAN_PROFILER_ENABLED", True):
            sp.record_response("/api/vuln", 0.1, 200)
            sp.record_finding("/api/vuln")
            sp.record_finding("/api/vuln")
            sp.record_finding("/api/vuln")
        rec = sp.get_recommendation("/api/vuln")
        assert rec["depth_modifier"] >= 1


# ── Base Exploiter Phoenix Integration ───────────────────────────


class TestBaseExploiterPhoenix:
    """Test Phoenix v10.0 additions to BaseExploiter."""

    def _make_dummy_exploiter(self):
        from exploits.base_exploiter import BaseExploiter

        class DummyExploiter(BaseExploiter):
            def run(self, target, endpoints):
                return []

        return DummyExploiter(session=MagicMock())

    def test_has_param_deduplicator(self):
        from core.param_deduplicator import SmartParamDeduplicator
        exp = self._make_dummy_exploiter()
        assert hasattr(exp, "param_deduplicator")
        assert isinstance(exp.param_deduplicator, SmartParamDeduplicator)

    def test_has_context_validator(self):
        from core.context_validator import ContextValidator
        exp = self._make_dummy_exploiter()
        assert hasattr(exp, "context_validator")
        assert isinstance(exp.context_validator, ContextValidator)

    def test_has_payload_minimizer(self):
        from core.payload_minimizer import PayloadMinimizer
        exp = self._make_dummy_exploiter()
        assert hasattr(exp, "payload_minimizer")
        assert isinstance(exp.payload_minimizer, PayloadMinimizer)

    def test_has_impact_analyzer(self):
        from core.impact_analyzer import ImpactAnalyzer
        exp = self._make_dummy_exploiter()
        assert hasattr(exp, "impact_analyzer")
        assert isinstance(exp.impact_analyzer, ImpactAnalyzer)

    def test_has_scan_profiler(self):
        from core.scan_profiler import ScanProfiler
        exp = self._make_dummy_exploiter()
        assert hasattr(exp, "scan_profiler")
        assert isinstance(exp.scan_profiler, ScanProfiler)

    def test_has_phoenix_flags(self):
        exp = self._make_dummy_exploiter()
        assert hasattr(exp, "_param_dedup")
        assert hasattr(exp, "_context_validation")
        assert hasattr(exp, "_payload_minimizer")
        assert hasattr(exp, "_impact_analysis")
        assert hasattr(exp, "_scan_profiling")

    def test_deduplicate_params_disabled(self):
        exp = self._make_dummy_exploiter()
        exp._param_dedup = False
        params = ["id", "user_id", "pk"]
        result = exp._deduplicate_params(params)
        assert result == params

    def test_minimize_payloads_disabled(self):
        exp = self._make_dummy_exploiter()
        exp._payload_minimizer = False
        payloads = ["' OR 1=1--", "<script>alert(1)</script>"]
        result = exp._minimize_payloads(payloads)
        assert result == payloads

    def test_get_scan_recommendation_disabled(self):
        exp = self._make_dummy_exploiter()
        exp._scan_profiling = False
        result = exp._get_scan_recommendation("/api/test")
        assert result["should_scan"] is True
        assert result["depth_modifier"] == 0
        assert result["delay_suggestion"] == 0.0

    def test_deduplicate_params_enabled(self):
        exp = self._make_dummy_exploiter()
        exp._param_dedup = True
        params = ["id", "user_id", "account_id", "pk", "ref", "index", "num"]
        result = exp._deduplicate_params(params)
        assert isinstance(result, list)

    def test_minimize_payloads_enabled(self):
        exp = self._make_dummy_exploiter()
        exp._payload_minimizer = True
        payloads = ["' OR 1=1--", "<script>alert(1)</script>", "| ls"]
        result = exp._minimize_payloads(payloads)
        assert isinstance(result, list)

    def test_record_scan_observation_disabled(self):
        exp = self._make_dummy_exploiter()
        exp._scan_profiling = False
        exp._record_scan_observation("/api/test", 0.1, 200)  # Should not raise


# ── Engine Phoenix Integration ───────────────────────────────────


class TestEnginePhoenixModules:
    """Test that Phoenix modules are registered in the engine."""

    def test_engine_accepts_phoenix_depth(self):
        from core.engine import ScanEngine
        engine = ScanEngine(enable_integrations=False, depth="phoenix")
        assert engine.depth == "phoenix"

    def test_phoenix_depth_preset_loaded(self):
        from core.engine import ScanEngine
        engine = ScanEngine(enable_integrations=False, depth="phoenix")
        preset = engine.depth_preset
        assert preset.get("param_deduplication") is True
        assert preset.get("context_validation") is True
        assert preset.get("payload_minimization") is True
        assert preset.get("impact_analysis") is True
        assert preset.get("scan_profiling") is True
        assert preset["crawl_depth"] == 25
        assert preset["max_crawl_pages"] == 15000

    def test_phoenix_inherits_all_previous_flags(self):
        from core.engine import ScanEngine
        engine = ScanEngine(enable_integrations=False, depth="phoenix")
        preset = engine.depth_preset
        # Chimera flags
        assert preset.get("adaptive_rate_limiting") is True
        assert preset.get("vulnerability_correlation") is True
        assert preset.get("scan_optimization") is True
        assert preset.get("sarif_output") is True
        assert preset.get("parameter_tampering") is True
        # Hydra flags
        assert preset.get("smart_payload_selection") is True
        assert preset.get("attack_chain_correlation") is True
        # Titan flags
        assert preset.get("oob_verification") is True
        assert preset.get("payload_mutation") is True
        # Quantum flags
        assert preset.get("cross_correlation") is True
        assert preset.get("entropy_analysis") is True

    def test_default_depth_is_standard(self):
        from core.engine import ScanEngine
        import config
        engine = ScanEngine(enable_integrations=False)
        assert engine.depth == config.SCAN_DEPTH
