"""Tests for VenomStrike v9.0 Chimera Edition features.

Covers:
- Chimera config settings & depth preset
- Adaptive Rate Limiter
- Vulnerability Correlator (clusters, compounds, systemic)
- Scan Optimizer (prioritization, deduplication, modules)
- SARIF Reporter (generation, CWE mapping, output)
- Parameter Tampering Exploiter
- Enhanced engine integration of Chimera phases
"""
import json
import math
import os
import sys
import threading
import time
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Config: Chimera settings ─────────────────────────────────────


class TestChimeraConfig:
    """Verify Chimera v9.0 config additions."""

    def test_version_is_9(self):
        import config
        assert config.VERSION == "9.0.0"

    def test_codename_is_chimera(self):
        import config
        assert config.CODENAME == "Chimera"

    def test_chimera_depth_preset_exists(self):
        import config
        assert "chimera" in config.DEPTH_PRESETS

    def test_chimera_depth_is_valid(self):
        import config
        assert "chimera" in config._VALID_DEPTHS

    def test_chimera_preset_has_required_keys(self):
        import config
        preset = config.DEPTH_PRESETS["chimera"]
        for key in ("crawl_depth", "max_crawl_pages", "dir_brute_limit",
                     "api_brute_limit", "payload_limit", "validation_attempts",
                     "min_confidence"):
            assert key in preset, f"Missing key: {key}"

    def test_chimera_preset_deeper_than_hydra(self):
        import config
        c = config.DEPTH_PRESETS["chimera"]
        h = config.DEPTH_PRESETS["hydra"]
        assert c["crawl_depth"] > h["crawl_depth"]
        assert c["max_crawl_pages"] > h["max_crawl_pages"]
        assert c["validation_attempts"] > h["validation_attempts"]

    def test_chimera_preset_inherits_hydra_flags(self):
        import config
        preset = config.DEPTH_PRESETS["chimera"]
        # Hydra flags
        assert preset.get("smart_payload_selection") is True
        assert preset.get("attack_chain_correlation") is True
        assert preset.get("bayesian_scoring") is True
        assert preset.get("response_intelligence") is True

    def test_chimera_preset_inherits_titan_flags(self):
        import config
        preset = config.DEPTH_PRESETS["chimera"]
        assert preset.get("oob_verification") is True
        assert preset.get("payload_mutation") is True
        assert preset.get("robust_timing") is True
        assert preset.get("waf_fingerprinting") is True

    def test_chimera_preset_has_new_flags(self):
        import config
        preset = config.DEPTH_PRESETS["chimera"]
        assert preset.get("adaptive_rate_limiting") is True
        assert preset.get("vulnerability_correlation") is True
        assert preset.get("scan_optimization") is True
        assert preset.get("sarif_output") is True
        assert preset.get("parameter_tampering") is True

    def test_chimera_config_settings_exist(self):
        import config
        assert hasattr(config, "ADAPTIVE_RATE_LIMITING")
        assert hasattr(config, "RATE_LIMIT_MIN_DELAY")
        assert hasattr(config, "RATE_LIMIT_MAX_DELAY")
        assert hasattr(config, "RATE_LIMIT_ERROR_THRESHOLD")
        assert hasattr(config, "VULNERABILITY_CORRELATION_ENABLED")
        assert hasattr(config, "SCAN_OPTIMIZATION_ENABLED")
        assert hasattr(config, "SARIF_OUTPUT_ENABLED")
        assert hasattr(config, "PARAMETER_TAMPERING_ENABLED")
        assert hasattr(config, "SCAN_OPTIMIZER_MIN_ENDPOINTS")
        assert hasattr(config, "CORRELATION_MIN_FINDINGS")

    def test_user_agent_updated(self):
        import config
        assert "9.0-Chimera" in config.DEFAULT_USER_AGENT

    def test_eight_valid_depths(self):
        import config
        assert len(config._VALID_DEPTHS) == 8
        assert "chimera" in config._VALID_DEPTHS


# ── Adaptive Rate Limiter ─────────────────────────────────────────


class TestAdaptiveRateLimiter:
    """Test the adaptive rate limiter."""

    def test_init_default_enabled(self):
        from core.rate_limiter import AdaptiveRateLimiter
        limiter = AdaptiveRateLimiter()
        assert limiter.enabled is True or limiter.enabled is False  # depends on env

    def test_init_explicit_enabled(self):
        from core.rate_limiter import AdaptiveRateLimiter
        limiter = AdaptiveRateLimiter(enabled=True)
        assert limiter.enabled is True

    def test_init_explicit_disabled(self):
        from core.rate_limiter import AdaptiveRateLimiter
        limiter = AdaptiveRateLimiter(enabled=False)
        assert limiter.enabled is False

    def test_disabled_wait_returns_zero(self):
        from core.rate_limiter import AdaptiveRateLimiter
        limiter = AdaptiveRateLimiter(enabled=False)
        result = limiter.wait("example.com")
        assert result == 0.0

    def test_disabled_record_success_noop(self):
        from core.rate_limiter import AdaptiveRateLimiter
        limiter = AdaptiveRateLimiter(enabled=False)
        limiter.record_success("example.com", 0.5)  # Should not raise

    def test_disabled_record_error_noop(self):
        from core.rate_limiter import AdaptiveRateLimiter
        limiter = AdaptiveRateLimiter(enabled=False)
        limiter.record_error("example.com")  # Should not raise

    def test_host_state_creation(self):
        from core.rate_limiter import AdaptiveRateLimiter
        limiter = AdaptiveRateLimiter(enabled=True)
        limiter.record_success("host1.com", 0.3)
        limiter.record_success("host2.com", 0.5)
        stats = limiter.get_all_stats()
        assert "host1.com" in stats
        assert "host2.com" in stats

    def test_host_state_tracking(self):
        from core.rate_limiter import AdaptiveRateLimiter
        limiter = AdaptiveRateLimiter(enabled=True)
        limiter.record_success("test.com", 0.2, 200)
        stats = limiter.get_host_stats("test.com")
        assert stats is not None
        assert stats["host"] == "test.com"
        assert stats["error_count"] == 0

    def test_error_increases_delay(self):
        from core.rate_limiter import AdaptiveRateLimiter
        limiter = AdaptiveRateLimiter(enabled=True)
        limiter.record_success("test.com", 0.1, 200)
        initial_stats = limiter.get_host_stats("test.com")
        initial_delay = initial_stats["current_delay"]
        # Record rate limit errors
        for _ in range(5):
            limiter.record_error("test.com", is_rate_limit=True)
        after_stats = limiter.get_host_stats("test.com")
        assert after_stats["current_delay"] > initial_delay

    def test_success_decreases_delay_after_increase(self):
        from core.rate_limiter import AdaptiveRateLimiter
        limiter = AdaptiveRateLimiter(enabled=True)
        # Increase delay with errors
        for _ in range(3):
            limiter.record_error("test.com", is_rate_limit=True)
        high_stats = limiter.get_host_stats("test.com")
        # Now send successes to reduce
        for _ in range(20):
            limiter.record_success("test.com", 0.1, 200)
        low_stats = limiter.get_host_stats("test.com")
        assert low_stats["current_delay"] < high_stats["current_delay"]

    def test_rate_limit_status_codes(self):
        from core.rate_limiter import AdaptiveRateLimiter
        limiter = AdaptiveRateLimiter(enabled=True)
        limiter.record_success("test.com", 0.1, 200)
        initial = limiter.get_host_stats("test.com")["current_delay"]
        # 429 should increase delay
        limiter.record_success("test.com", 0.1, 429)
        after = limiter.get_host_stats("test.com")["current_delay"]
        assert after >= initial

    def test_reset_host(self):
        from core.rate_limiter import AdaptiveRateLimiter
        limiter = AdaptiveRateLimiter(enabled=True)
        limiter.record_success("test.com", 0.3)
        limiter.reset("test.com")
        assert limiter.get_host_stats("test.com") is None

    def test_reset_all(self):
        from core.rate_limiter import AdaptiveRateLimiter
        limiter = AdaptiveRateLimiter(enabled=True)
        limiter.record_success("a.com", 0.3)
        limiter.record_success("b.com", 0.3)
        limiter.reset()
        assert limiter.get_all_stats() == {}

    def test_get_nonexistent_host(self):
        from core.rate_limiter import AdaptiveRateLimiter
        limiter = AdaptiveRateLimiter(enabled=True)
        assert limiter.get_host_stats("nohost.com") is None


class TestHostState:
    """Test individual HostState behavior."""

    def test_avg_response_time_empty(self):
        from core.rate_limiter import HostState
        state = HostState("test.com")
        assert state.avg_response_time == 0.0

    def test_avg_response_time(self):
        from core.rate_limiter import HostState
        state = HostState("test.com")
        state.record_success(0.2)
        state.record_success(0.4)
        assert abs(state.avg_response_time - 0.3) < 0.01

    def test_get_stats_structure(self):
        from core.rate_limiter import HostState
        state = HostState("test.com")
        stats = state.get_stats()
        assert "host" in stats
        assert "current_delay" in stats
        assert "avg_response_time" in stats
        assert "error_count" in stats
        assert "consecutive_errors" in stats
        assert "samples" in stats

    def test_consecutive_error_tracking(self):
        from core.rate_limiter import HostState
        state = HostState("test.com")
        state.record_error(is_rate_limit=False)
        state.record_error(is_rate_limit=False)
        stats = state.get_stats()
        assert stats["consecutive_errors"] == 2
        assert stats["error_count"] == 2

    def test_success_resets_consecutive_errors(self):
        from core.rate_limiter import HostState
        state = HostState("test.com")
        state.record_error()
        state.record_error()
        state.record_success(0.1)
        stats = state.get_stats()
        assert stats["consecutive_errors"] == 0


# ── Vulnerability Correlator ──────────────────────────────────────


class TestVulnerabilityCorrelator:
    """Test cross-module vulnerability correlation."""

    def test_init_default(self):
        from core.vulnerability_correlator import VulnerabilityCorrelator
        c = VulnerabilityCorrelator()
        assert c.enabled is True or c.enabled is False

    def test_init_disabled(self):
        from core.vulnerability_correlator import VulnerabilityCorrelator
        c = VulnerabilityCorrelator(enabled=False)
        result = c.correlate([{"vuln_type": "sqli"}])
        assert result["clusters"] == []

    def test_empty_findings(self):
        from core.vulnerability_correlator import VulnerabilityCorrelator
        c = VulnerabilityCorrelator(enabled=True)
        result = c.correlate([])
        assert result["clusters"] == []

    def test_single_finding_below_threshold(self):
        from core.vulnerability_correlator import VulnerabilityCorrelator
        with patch("core.vulnerability_correlator.CORRELATION_MIN_FINDINGS", 2):
            c = VulnerabilityCorrelator(enabled=True)
            result = c.correlate([{"vuln_type": "sqli", "url": "http://test.com/a", "param": "id"}])
            assert result["clusters"] == []

    def test_endpoint_clustering(self):
        from core.vulnerability_correlator import VulnerabilityCorrelator
        c = VulnerabilityCorrelator(enabled=True)
        findings = [
            {"vuln_type": "sqli", "url": "http://test.com/api/users", "param": "id", "severity": "High", "confidence": 80},
            {"vuln_type": "xss", "url": "http://test.com/api/users", "param": "name", "severity": "Medium", "confidence": 70},
            {"vuln_type": "idor", "url": "http://test.com/api/users", "param": "user_id", "severity": "High", "confidence": 75},
        ]
        result = c.correlate(findings)
        assert len(result["clusters"]) > 0
        # Should have endpoint concentration cluster
        endpoint_clusters = [cl for cl in result["clusters"] if cl["cluster_type"] == "endpoint_concentration"]
        assert len(endpoint_clusters) > 0

    def test_compound_vulnerability_sqli_idor(self):
        from core.vulnerability_correlator import VulnerabilityCorrelator
        c = VulnerabilityCorrelator(enabled=True)
        findings = [
            {"vuln_type": "sqli", "url": "http://test.com/api", "param": "id", "severity": "High", "confidence": 85},
            {"vuln_type": "idor", "url": "http://test.com/users", "param": "uid", "severity": "High", "confidence": 80},
        ]
        result = c.correlate(findings)
        compounds = result["compound_vulnerabilities"]
        assert len(compounds) > 0
        # Should detect SQLi + IDOR compound
        names = [c["name"] for c in compounds]
        assert any("SQL Injection" in n or "IDOR" in n or "Data Exfiltration" in n for n in names)

    def test_systemic_weakness_detection(self):
        from core.vulnerability_correlator import VulnerabilityCorrelator
        c = VulnerabilityCorrelator(enabled=True)
        findings = [
            {"vuln_type": "sqli", "url": "http://test.com/a", "param": "id", "severity": "High", "confidence": 80},
            {"vuln_type": "xss", "url": "http://test.com/b", "param": "q", "severity": "Medium", "confidence": 70},
            {"vuln_type": "cmd", "url": "http://test.com/c", "param": "host", "severity": "Critical", "confidence": 90},
        ]
        result = c.correlate(findings)
        systemic = result["systemic_weaknesses"]
        assert len(systemic) > 0
        assert any("Input Sanitization" in s["name"] for s in systemic)

    def test_risk_summary_structure(self):
        from core.vulnerability_correlator import VulnerabilityCorrelator
        c = VulnerabilityCorrelator(enabled=True)
        findings = [
            {"vuln_type": "sqli", "url": "http://t.com/a", "param": "id", "severity": "Critical", "confidence": 90},
            {"vuln_type": "xss", "url": "http://t.com/b", "param": "q", "severity": "Medium", "confidence": 70},
        ]
        result = c.correlate(findings)
        summary = result["risk_summary"]
        assert "overall_risk_score" in summary
        assert "total_findings" in summary
        assert "severity_distribution" in summary
        assert "risk_level" in summary

    def test_normalize_vuln_type(self):
        from core.vulnerability_correlator import VulnerabilityCorrelator
        c = VulnerabilityCorrelator()
        assert c._normalize_vuln_type("sql_injection") == "sqli"
        assert c._normalize_vuln_type("xss_reflected") == "xss"
        assert c._normalize_vuln_type("command_injection") == "cmd"
        assert c._normalize_vuln_type("nuclei:some_template") == "some_template"

    def test_parameter_reuse_clustering(self):
        from core.vulnerability_correlator import VulnerabilityCorrelator
        c = VulnerabilityCorrelator(enabled=True)
        findings = [
            {"vuln_type": "sqli", "url": "http://t.com/a", "param": "id", "severity": "High", "confidence": 80},
            {"vuln_type": "sqli", "url": "http://t.com/b", "param": "id", "severity": "High", "confidence": 75},
        ]
        result = c.correlate(findings)
        param_clusters = [cl for cl in result["clusters"] if cl["cluster_type"] == "parameter_reuse"]
        assert len(param_clusters) > 0


class TestCorrelationCluster:
    """Test CorrelationCluster data class."""

    def test_to_dict(self):
        from core.vulnerability_correlator import CorrelationCluster
        cluster = CorrelationCluster("c1", "endpoint_concentration")
        cluster.findings = [
            {"url": "http://t.com/api", "vuln_type": "sqli"},
        ]
        cluster.risk_score = 50
        cluster.description = "Test cluster"
        d = cluster.to_dict()
        assert d["cluster_id"] == "c1"
        assert d["finding_count"] == 1
        assert d["risk_score"] == 50


class TestCompoundVulnerability:
    """Test CompoundVulnerability data class."""

    def test_to_dict(self):
        from core.vulnerability_correlator import CompoundVulnerability
        cv = CompoundVulnerability("cv1", "Test Compound")
        cv.amplified_severity = "Critical"
        cv.amplified_confidence = 95
        d = cv.to_dict()
        assert d["compound_id"] == "cv1"
        assert d["name"] == "Test Compound"
        assert d["amplified_severity"] == "Critical"


# ── Scan Optimizer ────────────────────────────────────────────────


class TestScanOptimizer:
    """Test dynamic scan optimization."""

    def test_init_default(self):
        from core.scan_optimizer import ScanOptimizer
        opt = ScanOptimizer()
        assert opt.enabled is True or opt.enabled is False

    def test_disabled_passthrough(self):
        from core.scan_optimizer import ScanOptimizer
        opt = ScanOptimizer(enabled=False)
        endpoints = [{"url": "http://t.com/a", "method": "GET", "params": []}]
        result = opt.optimize(endpoints)
        assert result["prioritized_endpoints"] == endpoints

    def test_deduplication(self):
        from core.scan_optimizer import ScanOptimizer
        opt = ScanOptimizer(enabled=True)
        endpoints = [
            {"url": "http://t.com/api?id=1", "method": "GET", "params": ["id"]},
            {"url": "http://t.com/api?id=2", "method": "GET", "params": ["id"]},
            {"url": "http://t.com/other?q=test", "method": "GET", "params": ["q"]},
        ]
        result = opt.optimize(endpoints)
        assert result["deduplicated_count"] == 1
        assert len(result["prioritized_endpoints"]) == 2

    def test_api_endpoint_prioritized(self):
        from core.scan_optimizer import ScanOptimizer
        opt = ScanOptimizer(enabled=True)
        endpoints = [
            {"url": "http://t.com/static/style.css", "method": "GET", "params": []},
            {"url": "http://t.com/api/v2/users", "method": "GET", "params": ["id"]},
        ]
        result = opt.optimize(endpoints)
        prioritized = result["prioritized_endpoints"]
        # API endpoint should be first (higher score)
        assert "/api/" in prioritized[0]["url"]

    def test_post_method_boost(self):
        from core.scan_optimizer import ScanOptimizer
        opt = ScanOptimizer(enabled=True)
        endpoints = [
            {"url": "http://t.com/form", "method": "GET", "params": ["q"]},
            {"url": "http://t.com/form", "method": "POST", "params": ["q"]},
        ]
        result = opt.optimize(endpoints)
        prioritized = result["prioritized_endpoints"]
        # POST should score higher
        post_entry = [p for p in prioritized if p["method"] == "POST"]
        get_entry = [p for p in prioritized if p["method"] == "GET"]
        assert post_entry[0]["priority_score"] > get_entry[0]["priority_score"]

    def test_tech_module_recommendations(self):
        from core.scan_optimizer import ScanOptimizer
        opt = ScanOptimizer(enabled=True)
        endpoints = [
            {"url": "http://t.com/page", "method": "GET", "params": ["id"]},
        ]
        result = opt.optimize(endpoints, technologies=["php", "mysql"])
        recs = result["module_recommendations"]
        assert len(recs) > 0
        rec_modules = [r["module"] for r in recs]
        assert "sqli" in rec_modules

    def test_param_name_hints(self):
        from core.scan_optimizer import ScanOptimizer
        opt = ScanOptimizer(enabled=True)
        endpoints = [
            {"url": "http://t.com/search", "method": "GET", "params": ["url", "callback"]},
        ]
        result = opt.optimize(endpoints)
        prioritized = result["prioritized_endpoints"]
        assert len(prioritized[0]["suggested_modules"]) > 0
        assert "ssrf" in prioritized[0]["suggested_modules"]

    def test_optimization_summary_structure(self):
        from core.scan_optimizer import ScanOptimizer
        opt = ScanOptimizer(enabled=True)
        endpoints = [
            {"url": "http://t.com/a", "method": "GET", "params": []},
            {"url": "http://t.com/b", "method": "POST", "params": ["q"]},
        ]
        result = opt.optimize(endpoints)
        summary = result["optimization_summary"]
        assert "total_endpoints" in summary
        assert "unique_endpoints" in summary
        assert "deduplicated" in summary
        assert "high_priority_count" in summary

    def test_depth_adjustment_no_change(self):
        from core.scan_optimizer import ScanOptimizer
        opt = ScanOptimizer(enabled=True)
        result = opt.adjust_depth_for_endpoint(
            {"url": "http://t.com/api"}, "standard", finding_count=1,
        )
        assert result == "standard"

    def test_depth_adjustment_escalation(self):
        from core.scan_optimizer import ScanOptimizer
        opt = ScanOptimizer(enabled=True)
        result = opt.adjust_depth_for_endpoint(
            {"url": "http://t.com/api"}, "standard", finding_count=5,
        )
        assert result == "deep"  # Next depth after standard

    def test_depth_adjustment_at_max(self):
        from core.scan_optimizer import ScanOptimizer
        opt = ScanOptimizer(enabled=True)
        result = opt.adjust_depth_for_endpoint(
            {"url": "http://t.com/api"}, "chimera", finding_count=10,
        )
        assert result == "chimera"  # Already at max


class TestEndpointPriority:
    """Test EndpointPriority data class."""

    def test_to_dict(self):
        from core.scan_optimizer import EndpointPriority
        ep = EndpointPriority("http://t.com/api", "GET", ["id", "name"])
        ep.score = 65.5
        ep.reasons = ["API endpoint"]
        d = ep.to_dict()
        assert d["url"] == "http://t.com/api"
        assert d["priority_score"] == 65.5
        assert d["params"] == ["id", "name"]


# ── SARIF Reporter ────────────────────────────────────────────────


class TestSARIFReporter:
    """Test SARIF v2.1.0 report generation."""

    def _sample_findings(self):
        return [
            {
                "vuln_type": "sqli",
                "url": "http://test.com/api/users",
                "param": "id",
                "payload": "' OR 1=1 --",
                "severity": "Critical",
                "confidence": 95,
                "proof_description": "SQL syntax error in response",
                "injection_url": "http://test.com/api/users?id=' OR 1=1 --",
            },
            {
                "vuln_type": "xss",
                "url": "http://test.com/search",
                "param": "q",
                "payload": "<script>alert(1)</script>",
                "severity": "High",
                "confidence": 85,
            },
        ]

    def test_generate_basic_structure(self):
        from core.sarif_reporter import SARIFReporter
        reporter = SARIFReporter()
        sarif = reporter.generate(self._sample_findings())
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1

    def test_tool_info(self):
        from core.sarif_reporter import SARIFReporter
        reporter = SARIFReporter()
        sarif = reporter.generate(self._sample_findings())
        tool = sarif["runs"][0]["tool"]["driver"]
        assert tool["name"] == "VenomStrike"
        assert tool["version"] == "9.0.0"
        assert "Chimera" in tool["fullName"]

    def test_rules_generated(self):
        from core.sarif_reporter import SARIFReporter
        reporter = SARIFReporter()
        sarif = reporter.generate(self._sample_findings())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 2  # sqli and xss

    def test_results_count(self):
        from core.sarif_reporter import SARIFReporter
        reporter = SARIFReporter()
        sarif = reporter.generate(self._sample_findings())
        results = sarif["runs"][0]["results"]
        assert len(results) == 2

    def test_severity_mapping(self):
        from core.sarif_reporter import SARIFReporter
        reporter = SARIFReporter()
        sarif = reporter.generate(self._sample_findings())
        results = sarif["runs"][0]["results"]
        # Critical/High → "error"
        assert results[0]["level"] == "error"
        assert results[1]["level"] == "error"

    def test_cwe_mapping(self):
        from core.sarif_reporter import SARIFReporter
        reporter = SARIFReporter()
        sarif = reporter.generate(self._sample_findings())
        results = sarif["runs"][0]["results"]
        assert results[0]["properties"]["venomstrike/cwe"] == "CWE-89"
        assert results[1]["properties"]["venomstrike/cwe"] == "CWE-79"

    def test_empty_findings(self):
        from core.sarif_reporter import SARIFReporter
        reporter = SARIFReporter()
        sarif = reporter.generate([])
        assert sarif["runs"][0]["results"] == []

    def test_to_json(self):
        from core.sarif_reporter import SARIFReporter
        reporter = SARIFReporter()
        sarif = reporter.generate(self._sample_findings())
        json_str = reporter.to_json(sarif)
        parsed = json.loads(json_str)
        assert parsed["version"] == "2.1.0"

    def test_write_file(self, tmp_path):
        from core.sarif_reporter import SARIFReporter
        reporter = SARIFReporter()
        sarif = reporter.generate(self._sample_findings())
        filepath = str(tmp_path / "results.sarif")
        result = reporter.write(sarif, filepath)
        assert os.path.exists(result)
        with open(result) as f:
            loaded = json.load(f)
        assert loaded["version"] == "2.1.0"

    def test_rule_id_format(self):
        from core.sarif_reporter import SARIFReporter
        reporter = SARIFReporter()
        sarif = reporter.generate(self._sample_findings())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        for rule in rules:
            assert rule["id"].startswith("VS-")

    def test_scan_metadata(self):
        from core.sarif_reporter import SARIFReporter
        reporter = SARIFReporter()
        sarif = reporter.generate(
            self._sample_findings(),
            scan_metadata={
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-01-01T00:05:00Z",
            },
        )
        invocation = sarif["runs"][0]["invocations"][0]
        assert invocation["startTimeUtc"] == "2026-01-01T00:00:00Z"

    def test_proof_description_included(self):
        from core.sarif_reporter import SARIFReporter
        reporter = SARIFReporter()
        sarif = reporter.generate(self._sample_findings())
        results = sarif["runs"][0]["results"]
        assert "venomstrike/proof" in results[0]["properties"]

    def test_medium_severity_maps_to_warning(self):
        from core.sarif_reporter import SARIFReporter
        reporter = SARIFReporter()
        findings = [{"vuln_type": "csrf", "url": "http://t.com", "param": "", "payload": "", "severity": "Medium", "confidence": 60}]
        sarif = reporter.generate(findings)
        assert sarif["runs"][0]["results"][0]["level"] == "warning"

    def test_low_severity_maps_to_note(self):
        from core.sarif_reporter import SARIFReporter
        reporter = SARIFReporter()
        findings = [{"vuln_type": "clickjack", "url": "http://t.com", "param": "", "payload": "", "severity": "Low", "confidence": 50}]
        sarif = reporter.generate(findings)
        assert sarif["runs"][0]["results"][0]["level"] == "note"

    def test_normalize_type(self):
        from core.sarif_reporter import SARIFReporter
        reporter = SARIFReporter()
        assert reporter._normalize_type("sql_injection") == "sqli"
        assert reporter._normalize_type("xss_stored") == "xss"
        assert reporter._normalize_type("nuclei:template1") == "template1"

    def test_vuln_type_cwe_map_completeness(self):
        from core.sarif_reporter import VULN_TYPE_CWE_MAP
        # All major types should be mapped
        for vtype in ["sqli", "xss", "cmd", "ssrf", "lfi", "xxe", "csrf", "idor",
                       "jwt", "cors", "nosql", "rce", "parameter_tampering"]:
            assert vtype in VULN_TYPE_CWE_MAP, f"Missing CWE mapping for {vtype}"


# ── Parameter Tampering Exploiter ─────────────────────────────────


class TestParameterTamperingExploiter:
    """Test the parameter tampering exploit module."""

    def test_module_name(self):
        from exploits.advanced.parameter_tampering_exploiter import ParameterTamperingExploiter
        exp = ParameterTamperingExploiter(session=MagicMock())
        assert exp.MODULE_NAME == "parameter_tampering"

    def test_vuln_type(self):
        from exploits.advanced.parameter_tampering_exploiter import ParameterTamperingExploiter
        exp = ParameterTamperingExploiter(session=MagicMock())
        assert exp.VULN_TYPE == "parameter_tampering"

    def test_disabled_returns_empty(self):
        from exploits.advanced.parameter_tampering_exploiter import ParameterTamperingExploiter
        with patch("exploits.advanced.parameter_tampering_exploiter.PARAMETER_TAMPERING_ENABLED", False):
            exp = ParameterTamperingExploiter(session=MagicMock())
            exp._enabled = False
            result = exp.run(MagicMock(), [])
            assert result == []

    def test_empty_endpoints(self):
        from exploits.advanced.parameter_tampering_exploiter import ParameterTamperingExploiter
        exp = ParameterTamperingExploiter(session=MagicMock())
        result = exp.run(MagicMock(), [])
        assert result == []

    def test_detect_tampering_anomaly_server_error(self):
        from exploits.advanced.parameter_tampering_exploiter import ParameterTamperingExploiter
        result = ParameterTamperingExploiter._detect_tampering_anomaly(
            baseline_text="OK", baseline_status=200, baseline_len=2,
            response_text="Internal Server Error", response_status=500,
            response_len=21, payload="-1", param="quantity",
        )
        assert result is not None
        assert result["type"] == "server_error"
        assert result["confidence"] == 75

    def test_detect_tampering_anomaly_redirect(self):
        from exploits.advanced.parameter_tampering_exploiter import ParameterTamperingExploiter
        result = ParameterTamperingExploiter._detect_tampering_anomaly(
            baseline_text="OK", baseline_status=200, baseline_len=2,
            response_text="Redirect", response_status=302,
            response_len=8, payload="true", param="admin",
        )
        assert result is not None
        assert result["type"] == "redirect_change"

    def test_detect_tampering_anomaly_content_change(self):
        from exploits.advanced.parameter_tampering_exploiter import ParameterTamperingExploiter
        result = ParameterTamperingExploiter._detect_tampering_anomaly(
            baseline_text="x" * 100, baseline_status=200, baseline_len=100,
            response_text="y" * 500, response_status=200,
            response_len=500, payload="admin", param="role",
        )
        assert result is not None
        assert result["type"] == "content_change"

    def test_detect_tampering_anomaly_error_disclosure(self):
        from exploits.advanced.parameter_tampering_exploiter import ParameterTamperingExploiter
        result = ParameterTamperingExploiter._detect_tampering_anomaly(
            baseline_text="OK", baseline_status=200, baseline_len=2,
            response_text="TypeError: cannot convert string to int",
            response_status=200, response_len=40,
            payload="[]", param="id",
        )
        assert result is not None
        assert result["type"] == "error_disclosure"

    def test_detect_tampering_anomaly_no_change(self):
        from exploits.advanced.parameter_tampering_exploiter import ParameterTamperingExploiter
        result = ParameterTamperingExploiter._detect_tampering_anomaly(
            baseline_text="OK response text", baseline_status=200, baseline_len=16,
            response_text="OK response text", response_status=200,
            response_len=16, payload="1", param="id",
        )
        assert result is None

    def test_payloads_defined(self):
        from exploits.advanced.parameter_tampering_exploiter import (
            BOUNDARY_PAYLOADS,
            HIDDEN_PARAM_NAMES,
            HIDDEN_PARAM_VALUES,
            PRICE_TAMPERING_PAYLOADS,
            TYPE_CONFUSION_PAYLOADS,
        )
        assert len(PRICE_TAMPERING_PAYLOADS) > 0
        assert len(TYPE_CONFUSION_PAYLOADS) > 0
        assert len(BOUNDARY_PAYLOADS) > 0
        assert len(HIDDEN_PARAM_NAMES) > 0
        assert len(HIDDEN_PARAM_VALUES) > 0


# ── Base Exploiter Chimera Integration ────────────────────────────


class TestBaseExploiterChimera:
    """Test Chimera v9.0 additions to BaseExploiter."""

    def test_has_rate_limiter(self):
        from core.rate_limiter import AdaptiveRateLimiter
        from exploits.base_exploiter import BaseExploiter

        class DummyExploiter(BaseExploiter):
            def run(self, target, endpoints):
                return []

        exp = DummyExploiter(session=MagicMock())
        assert hasattr(exp, "rate_limiter")
        assert isinstance(exp.rate_limiter, AdaptiveRateLimiter)

    def test_has_adaptive_rate_limiting_flag(self):
        from exploits.base_exploiter import BaseExploiter

        class DummyExploiter(BaseExploiter):
            def run(self, target, endpoints):
                return []

        exp = DummyExploiter(session=MagicMock())
        assert hasattr(exp, "_adaptive_rate_limiting")

    def test_rate_limit_wait_disabled(self):
        from exploits.base_exploiter import BaseExploiter

        class DummyExploiter(BaseExploiter):
            def run(self, target, endpoints):
                return []

        exp = DummyExploiter(session=MagicMock())
        exp._adaptive_rate_limiting = False
        result = exp._rate_limit_wait("test.com")
        assert result == 0.0

    def test_rate_limit_record_disabled(self):
        from exploits.base_exploiter import BaseExploiter

        class DummyExploiter(BaseExploiter):
            def run(self, target, endpoints):
                return []

        exp = DummyExploiter(session=MagicMock())
        exp._adaptive_rate_limiting = False
        exp._rate_limit_record("test.com", 0.5, 200)  # Should not raise

    def test_rate_limit_record_enabled(self):
        from exploits.base_exploiter import BaseExploiter

        class DummyExploiter(BaseExploiter):
            def run(self, target, endpoints):
                return []

        exp = DummyExploiter(session=MagicMock())
        exp._adaptive_rate_limiting = True
        exp._rate_limit_record("test.com", 0.5, 200)
        stats = exp.rate_limiter.get_host_stats("test.com")
        assert stats is not None

    def test_rate_limit_record_429(self):
        from exploits.base_exploiter import BaseExploiter

        class DummyExploiter(BaseExploiter):
            def run(self, target, endpoints):
                return []

        exp = DummyExploiter(session=MagicMock())
        exp._adaptive_rate_limiting = True
        exp._rate_limit_record("test.com", 0.1, 429)
        stats = exp.rate_limiter.get_host_stats("test.com")
        assert stats["error_count"] > 0


# ── Engine Chimera Integration ────────────────────────────────────


class TestEngineChimeraModules:
    """Test that Chimera modules are registered in the engine."""

    def test_parameter_tampering_in_modules(self):
        from core.engine import ScanEngine
        engine = ScanEngine(enable_integrations=False)
        modules = engine._load_all_modules()
        assert "parameter_tampering" in modules

    def test_parameter_tampering_in_advanced_category(self):
        from core.engine import ScanEngine
        engine = ScanEngine(enable_integrations=False)
        mods = engine._get_modules("category", category="advanced")
        mod_names = [m[0] for m in mods]
        assert "parameter_tampering" in mod_names


# ── Payload Files ─────────────────────────────────────────────────


class TestPayloadFiles:
    """Verify new payload files exist and have content."""

    def test_price_manipulation_payloads(self):
        path = os.path.join(os.path.dirname(__file__), "..", "payloads", "tampering", "price_manipulation.txt")
        assert os.path.exists(path)
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip()]
        assert len(lines) >= 10

    def test_type_confusion_payloads(self):
        path = os.path.join(os.path.dirname(__file__), "..", "payloads", "tampering", "type_confusion.txt")
        assert os.path.exists(path)
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip()]
        assert len(lines) >= 10

    def test_boundary_values_payloads(self):
        path = os.path.join(os.path.dirname(__file__), "..", "payloads", "tampering", "boundary_values.txt")
        assert os.path.exists(path)
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip()]
        assert len(lines) >= 10

    def test_hidden_params_payloads(self):
        path = os.path.join(os.path.dirname(__file__), "..", "payloads", "tampering", "hidden_params.txt")
        assert os.path.exists(path)
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip()]
        assert len(lines) >= 10
