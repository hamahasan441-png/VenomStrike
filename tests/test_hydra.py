"""Tests for VenomStrike v8.0 Hydra Edition features.

Covers:
- Hydra config settings & depth preset
- Smart Payload Selection Engine
- Attack Chain Correlator
- Bayesian Confidence Scorer
- Response Intelligence Analyzer
- New exploit modules (deserialization, API key exposure, HTTP/2 desync)
- Enhanced evidence proof descriptions
- Engine integration of Hydra phases
"""
import os
import sys
import math
import time
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Config: Hydra settings ────────────────────────────────────────


class TestHydraConfig:
    """Verify Hydra v8.0 config additions."""

    def test_version_is_8(self):
        import config
        assert config.VERSION == "9.0.0"

    def test_codename_is_hydra(self):
        import config
        assert config.CODENAME == "Chimera"

    def test_hydra_depth_preset_exists(self):
        import config
        assert "hydra" in config.DEPTH_PRESETS

    def test_hydra_depth_is_valid(self):
        import config
        assert "hydra" in config._VALID_DEPTHS

    def test_hydra_preset_has_required_keys(self):
        import config
        preset = config.DEPTH_PRESETS["hydra"]
        for key in ("crawl_depth", "max_crawl_pages", "dir_brute_limit",
                     "api_brute_limit", "payload_limit", "validation_attempts",
                     "min_confidence"):
            assert key in preset, f"Missing key: {key}"

    def test_hydra_preset_deeper_than_titan(self):
        import config
        h = config.DEPTH_PRESETS["hydra"]
        t = config.DEPTH_PRESETS["titan"]
        assert h["crawl_depth"] > t["crawl_depth"]
        assert h["max_crawl_pages"] > t["max_crawl_pages"]
        assert h["validation_attempts"] > t["validation_attempts"]

    def test_hydra_preset_inherits_titan_flags(self):
        import config
        preset = config.DEPTH_PRESETS["hydra"]
        # Titan flags
        assert preset.get("oob_verification") is True
        assert preset.get("payload_mutation") is True
        assert preset.get("robust_timing") is True
        assert preset.get("waf_fingerprinting") is True
        # Quantum flags
        assert preset.get("cross_correlation") is True
        assert preset.get("entropy_analysis") is True
        assert preset.get("triple_confirm") is True
        assert preset.get("statistical_confidence") is True

    def test_hydra_preset_has_hydra_flags(self):
        import config
        preset = config.DEPTH_PRESETS["hydra"]
        assert preset.get("smart_payload_selection") is True
        assert preset.get("attack_chain_correlation") is True
        assert preset.get("bayesian_scoring") is True
        assert preset.get("response_intelligence") is True
        assert preset.get("adaptive_exploitation") is True

    def test_hydra_config_keys_exist(self):
        import config
        assert hasattr(config, "SMART_PAYLOAD_SELECTION")
        assert hasattr(config, "ATTACK_CHAIN_CORRELATION")
        assert hasattr(config, "BAYESIAN_SCORING_ENABLED")
        assert hasattr(config, "RESPONSE_INTELLIGENCE_ENABLED")
        assert hasattr(config, "ADAPTIVE_EXPLOITATION")
        assert hasattr(config, "BAYESIAN_PRIOR_CONFIDENCE")
        assert hasattr(config, "ATTACK_CHAIN_MAX_DEPTH")
        assert hasattr(config, "SMART_PAYLOAD_TOP_N")

    def test_user_agent_contains_hydra(self):
        import config
        assert "Chimera" in config.DEFAULT_USER_AGENT
        assert "9.0" in config.DEFAULT_USER_AGENT

    def test_depth_presets_ordering_includes_hydra(self):
        """Hydra should have highest crawl_depth of all levels."""
        import config
        levels = ["quick", "standard", "deep", "full", "quantum", "titan", "hydra"]
        for i in range(len(levels) - 1):
            a = config.DEPTH_PRESETS[levels[i]]
            b = config.DEPTH_PRESETS[levels[i + 1]]
            assert a["crawl_depth"] <= b["crawl_depth"]
            assert a["max_crawl_pages"] <= b["max_crawl_pages"]

    def test_bayesian_prior_range(self):
        import config
        assert 0.01 <= config.BAYESIAN_PRIOR_CONFIDENCE <= 0.99

    def test_smart_payload_top_n_range(self):
        import config
        assert 5 <= config.SMART_PAYLOAD_TOP_N <= 200

    def test_attack_chain_max_depth_range(self):
        import config
        assert 1 <= config.ATTACK_CHAIN_MAX_DEPTH <= 20


# ── Smart Payload Selection ────────────────────────────────────────


class TestSmartPayloadSelector:
    """Test context-aware payload prioritization."""

    def test_basic_prioritization(self):
        from core.smart_selector import SmartPayloadSelector
        selector = SmartPayloadSelector()
        payloads = ["' OR 1=1 --", "<script>alert(1)</script>", "normal_value"]
        result = selector.prioritize(payloads)
        assert len(result) == 3
        assert isinstance(result, list)

    def test_tech_boost_mysql(self):
        from core.smart_selector import SmartPayloadSelector
        selector = SmartPayloadSelector()
        payloads = [
            "' UNION SELECT NULL--",  # Has UNION (MySQL keyword)
            "<script>alert(1)</script>",  # XSS, not SQL
        ]
        result = selector.prioritize(
            payloads, context={"technology": "mysql"}, vuln_type="sqli",
        )
        # MySQL payload should rank higher
        assert result[0] == "' UNION SELECT NULL--"

    def test_param_affinity_sqli(self):
        from core.smart_selector import SmartPayloadSelector
        selector = SmartPayloadSelector()
        payloads = ["test1", "test2"]
        # Scoring with id param should boost sqli
        score1 = selector._score_payload(
            "' OR 1=1", {"param_name": "id"}, "sqli"
        )
        score2 = selector._score_payload(
            "' OR 1=1", {"param_name": "random_field"}, "sqli"
        )
        assert score1 > score2

    def test_waf_bypass_boost(self):
        from core.smart_selector import SmartPayloadSelector
        selector = SmartPayloadSelector()
        # WAF bypass payload with encoded chars
        waf_payload = "'%27 OR %271%27=%271 /*!SELECT*/"
        normal_payload = "' OR 1=1--"
        score_waf = selector._score_payload(
            waf_payload, {"waf_detected": True}, "sqli"
        )
        score_normal = selector._score_payload(
            normal_payload, {"waf_detected": True}, "sqli"
        )
        assert score_waf > score_normal

    def test_max_payloads_limit(self):
        from core.smart_selector import SmartPayloadSelector
        selector = SmartPayloadSelector()
        payloads = [f"payload_{i}" for i in range(50)]
        result = selector.prioritize(payloads, max_payloads=10)
        assert len(result) == 10

    def test_reflection_context_boost(self):
        from core.smart_selector import SmartPayloadSelector
        selector = SmartPayloadSelector()
        score = selector._score_payload(
            '" autofocus onfocus="alert(1)"',
            {"reflection_context": "attribute"},
            "xss",
        )
        base_score = selector._score_payload(
            '" autofocus onfocus="alert(1)"',
            {"reflection_context": "none"},
            "xss",
        )
        assert score > base_score

    def test_success_history_tracking(self):
        from core.smart_selector import SmartPayloadSelector
        selector = SmartPayloadSelector()
        selector.record_success("' OR 1=1 --")
        history = selector.get_success_history()
        assert "sqli" in history
        assert history["sqli"] >= 1

    def test_success_history_boosts_score(self):
        from core.smart_selector import SmartPayloadSelector
        selector = SmartPayloadSelector()
        score_before = selector._score_payload("' SLEEP(5)--", {}, "sqli")
        selector.record_success("' UNION SELECT NULL--")
        score_after = selector._score_payload("' SLEEP(5)--", {}, "sqli")
        assert score_after > score_before

    def test_categorize_payload(self):
        from core.smart_selector import SmartPayloadSelector
        assert SmartPayloadSelector._categorize_payload("' UNION SELECT") == "sqli"
        assert SmartPayloadSelector._categorize_payload("<script>alert(1)") == "xss"
        assert SmartPayloadSelector._categorize_payload("../../etc/passwd") == "lfi"
        assert SmartPayloadSelector._categorize_payload("http://169.254.169.254") == "ssrf"
        assert SmartPayloadSelector._categorize_payload("{{7*7}}") == "ssti"

    def test_empty_payloads(self):
        from core.smart_selector import SmartPayloadSelector
        selector = SmartPayloadSelector()
        assert selector.prioritize([]) == []


# ── Attack Chain Correlator ──────────────────────────────────────


class TestAttackChain:
    """Test AttackChain dataclass."""

    def test_create_chain(self):
        from core.attack_chain import AttackChain
        chain = AttackChain("chain_1")
        assert chain.chain_id == "chain_1"
        assert len(chain.stages) == 0

    def test_add_stage(self):
        from core.attack_chain import AttackChain
        chain = AttackChain("chain_1")
        finding = {"vuln_type": "sqli", "url": "http://test.com", "param": "id",
                    "severity": "Critical", "confidence": 90, "fingerprint": "abc"}
        chain.add_stage(finding, 1, "entry_point")
        assert len(chain.stages) == 1
        assert chain.stages[0]["role"] == "entry_point"
        assert chain.stages[0]["vuln_type"] == "sqli"

    def test_to_dict(self):
        from core.attack_chain import AttackChain
        chain = AttackChain("chain_1")
        chain.description = "Test chain"
        chain.impact_rating = 9
        d = chain.to_dict()
        assert d["chain_id"] == "chain_1"
        assert d["description"] == "Test chain"
        assert d["impact_rating"] == 9
        assert d["stage_count"] == 0


class TestAttackChainCorrelator:
    """Test attack chain detection."""

    def test_correlate_empty(self):
        from core.attack_chain import AttackChainCorrelator
        c = AttackChainCorrelator()
        chains = c.correlate([])
        assert chains == []

    def test_single_vuln_chain(self):
        from core.attack_chain import AttackChainCorrelator
        c = AttackChainCorrelator()
        findings = [
            {"vuln_type": "sqli", "url": "http://test.com?id=1", "param": "id",
             "severity": "Critical", "confidence": 90, "fingerprint": "abc"},
        ]
        chains = c.correlate(findings)
        # Should detect "SQLi to Data Exfiltration" chain
        assert len(chains) >= 1
        sqli_chain = next((ch for ch in chains if "SQL" in ch.description), None)
        assert sqli_chain is not None
        assert sqli_chain.impact_rating >= 8

    def test_multi_vuln_chain(self):
        from core.attack_chain import AttackChainCorrelator
        c = AttackChainCorrelator()
        findings = [
            {"vuln_type": "ssrf", "url": "http://test.com", "param": "url",
             "severity": "High", "confidence": 85, "fingerprint": "ssrf1"},
            {"vuln_type": "rce", "url": "http://test.com", "param": "cmd",
             "severity": "Critical", "confidence": 80, "fingerprint": "rce1"},
        ]
        chains = c.correlate(findings)
        # Should detect SSRF → RCE chain
        ssrf_chain = next((ch for ch in chains if "SSRF" in ch.description), None)
        assert ssrf_chain is not None
        assert len(ssrf_chain.stages) == 2
        assert ssrf_chain.stages[0]["role"] == "entry_point"
        assert ssrf_chain.stages[1]["role"] == "escalation"

    def test_xss_session_chain(self):
        from core.attack_chain import AttackChainCorrelator
        c = AttackChainCorrelator()
        findings = [
            {"vuln_type": "xss", "url": "http://test.com", "param": "q",
             "severity": "High", "confidence": 85, "fingerprint": "xss1"},
            {"vuln_type": "session", "url": "http://test.com", "param": "",
             "severity": "Medium", "confidence": 75, "fingerprint": "sess1"},
        ]
        chains = c.correlate(findings)
        xss_session = next((ch for ch in chains if "XSS" in ch.description), None)
        assert xss_session is not None

    def test_enrich_findings_with_chains(self):
        from core.attack_chain import AttackChainCorrelator, AttackChain
        c = AttackChainCorrelator()
        findings = [
            {"vuln_type": "sqli", "url": "http://test.com", "param": "id",
             "severity": "Critical", "confidence": 85, "fingerprint": "abc"},
        ]
        chains = c.correlate(findings)
        findings = c.enrich_findings_with_chains(findings, chains)
        # Finding should have attack_chains field
        assert "attack_chains" in findings[0]
        # Confidence should be boosted for high-impact chains
        assert findings[0]["confidence"] > 85

    def test_normalize_vuln_type(self):
        from core.attack_chain import AttackChainCorrelator
        assert AttackChainCorrelator._normalize_vuln_type("SQL_Injection") == "sqli"
        assert AttackChainCorrelator._normalize_vuln_type("xss_reflected") == "xss"
        assert AttackChainCorrelator._normalize_vuln_type("nuclei:cve-2021-1234") == "cve_2021_1234"
        assert AttackChainCorrelator._normalize_vuln_type("ssrf") == "ssrf"

    def test_chains_sorted_by_impact(self):
        from core.attack_chain import AttackChainCorrelator
        c = AttackChainCorrelator()
        findings = [
            {"vuln_type": "cmd", "confidence": 90, "fingerprint": "a",
             "url": "http://test.com", "param": "cmd", "severity": "Critical"},
            {"vuln_type": "open_redirect", "confidence": 80, "fingerprint": "b",
             "url": "http://test.com", "param": "next", "severity": "Low"},
        ]
        chains = c.correlate(findings)
        if len(chains) >= 2:
            assert chains[0].impact_rating >= chains[1].impact_rating

    def test_max_chains_limit(self):
        from core.attack_chain import AttackChainCorrelator
        c = AttackChainCorrelator()
        # Generate many findings
        findings = []
        for vt in ["sqli", "xss", "ssrf", "rce", "cmd", "ssti", "lfi",
                    "idor", "cors", "open_redirect"]:
            findings.append({"vuln_type": vt, "confidence": 90, "fingerprint": vt,
                            "url": "http://test.com", "param": "p", "severity": "High"})
        chains = c.correlate(findings, max_chains=3)
        assert len(chains) <= 3


# ── Bayesian Confidence Scorer ──────────────────────────────────


class TestBayesianConfidenceScorer:
    """Test Bayesian confidence scoring."""

    def test_basic_scoring(self):
        from core.bayesian_scorer import BayesianConfidenceScorer
        scorer = BayesianConfidenceScorer(prior=0.3)
        result = scorer.score({"error_pattern": True, "baseline_clean": True})
        assert 0 <= result["confidence"] <= 100
        assert result["signals_used"] == 2

    def test_high_confidence_with_multiple_signals(self):
        from core.bayesian_scorer import BayesianConfidenceScorer
        scorer = BayesianConfidenceScorer(prior=0.3)
        result = scorer.score({
            "error_pattern": True,
            "baseline_clean": True,
            "retest_confirmed": True,
        })
        assert result["confidence"] >= 90

    def test_oob_verified_very_high_confidence(self):
        from core.bayesian_scorer import BayesianConfidenceScorer
        scorer = BayesianConfidenceScorer(prior=0.3)
        result = scorer.score({"oob_verified": True})
        assert result["confidence"] >= 90

    def test_low_confidence_with_absent_evidence(self):
        from core.bayesian_scorer import BayesianConfidenceScorer
        scorer = BayesianConfidenceScorer(prior=0.3)
        result = scorer.score({
            "error_pattern": False,
            "retest_confirmed": False,
        })
        assert result["confidence"] < 10

    def test_prior_affects_result(self):
        from core.bayesian_scorer import BayesianConfidenceScorer
        scorer = BayesianConfidenceScorer()
        r1 = scorer.score({"error_pattern": True}, prior_override=0.1)
        r2 = scorer.score({"error_pattern": True}, prior_override=0.5)
        assert r2["confidence"] >= r1["confidence"]

    def test_combine_with_existing(self):
        from core.bayesian_scorer import BayesianConfidenceScorer
        scorer = BayesianConfidenceScorer()
        result = scorer.combine_with_existing(
            existing_confidence=60,
            evidence_signals={"retest_confirmed": True},
        )
        assert result["confidence"] > 60

    def test_classify_confidence(self):
        from core.bayesian_scorer import BayesianConfidenceScorer
        assert BayesianConfidenceScorer.classify_confidence(95) == "very_high"
        assert BayesianConfidenceScorer.classify_confidence(75) == "high"
        assert BayesianConfidenceScorer.classify_confidence(55) == "medium"
        assert BayesianConfidenceScorer.classify_confidence(35) == "low"
        assert BayesianConfidenceScorer.classify_confidence(15) == "very_low"

    def test_empty_signals(self):
        from core.bayesian_scorer import BayesianConfidenceScorer
        scorer = BayesianConfidenceScorer(prior=0.3)
        result = scorer.score({})
        # With no evidence, confidence should stay near prior
        assert 20 <= result["confidence"] <= 40
        assert result["signals_used"] == 0

    def test_evidence_contributions_logged(self):
        from core.bayesian_scorer import BayesianConfidenceScorer
        scorer = BayesianConfidenceScorer(prior=0.3)
        result = scorer.score({
            "error_pattern": True,
            "timing_confirmed": True,
        })
        assert "error_pattern" in result["evidence_contributions"]
        assert "timing_confirmed" in result["evidence_contributions"]
        # Log-odds shift should be positive for present evidence
        for signal, shift in result["evidence_contributions"].items():
            assert shift > 0

    def test_posterior_is_probability(self):
        from core.bayesian_scorer import BayesianConfidenceScorer
        scorer = BayesianConfidenceScorer(prior=0.3)
        result = scorer.score({"error_pattern": True})
        assert 0.0 <= result["posterior"] <= 1.0

    def test_triple_confirmed_very_high(self):
        from core.bayesian_scorer import BayesianConfidenceScorer
        scorer = BayesianConfidenceScorer(prior=0.3)
        result = scorer.score({"triple_confirmed": True})
        assert result["confidence"] >= 90

    def test_all_evidence_present(self):
        from core.bayesian_scorer import BayesianConfidenceScorer
        scorer = BayesianConfidenceScorer(prior=0.3)
        result = scorer.score({
            "error_pattern": True,
            "payload_reflected": True,
            "timing_confirmed": True,
            "response_diff": True,
            "baseline_clean": True,
            "retest_confirmed": True,
            "oob_verified": True,
        })
        assert result["confidence"] == 100


# ── Response Intelligence Analyzer ──────────────────────────────


class TestResponseIntelligence:
    """Test deep response analysis."""

    def test_detect_mysql_error(self):
        from core.response_intelligence import ResponseIntelligence
        analyzer = ResponseIntelligence()
        result = analyzer.analyze(
            baseline_text="Normal page content",
            payload_text="You have an error in your SQL syntax near '1'",
            technology="mysql",
        )
        assert result["is_anomalous"] is True
        assert len(result["error_signatures_found"]) >= 1
        assert result["error_signatures_found"][0]["technology"] == "mysql"

    def test_no_anomaly_in_baseline(self):
        from core.response_intelligence import ResponseIntelligence
        analyzer = ResponseIntelligence()
        # If error is in both baseline AND payload, not anomalous
        error_text = "You have an error in your SQL syntax"
        result = analyzer.analyze(
            baseline_text=error_text,
            payload_text=error_text,
            technology="mysql",
        )
        assert len(result["error_signatures_found"]) == 0

    def test_detect_python_traceback(self):
        from core.response_intelligence import ResponseIntelligence
        analyzer = ResponseIntelligence()
        result = analyzer.analyze(
            baseline_text="Normal response",
            payload_text='Traceback (most recent call last)\n  File "/app/views.py", line 42',
            technology="python",
        )
        assert result["is_anomalous"] is True
        assert any(
            e["leaks"] == "stack_trace"
            for e in result["error_signatures_found"]
        )

    def test_info_leak_detection(self):
        from core.response_intelligence import ResponseIntelligence
        analyzer = ResponseIntelligence()
        result = analyzer.analyze(
            baseline_text="Normal page",
            payload_text="Error in /home/app/views.py at line 42",
        )
        assert len(result["info_leaks"]) >= 1
        assert any(l["type"] == "file_path" for l in result["info_leaks"])

    def test_structural_diff(self):
        from core.response_intelligence import ResponseIntelligence
        analyzer = ResponseIntelligence()
        result = analyzer.analyze(
            baseline_text="<html><body>Normal</body></html>",
            payload_text="<html><body>Error<pre>Stack trace...</pre><div>Debug info</div>" * 10,
        )
        diff = result["structural_diff"]
        assert diff["baseline_length"] < diff["payload_length"]
        assert diff["length_ratio"] > 0

    def test_behavior_change_status_code(self):
        from core.response_intelligence import ResponseIntelligence
        analyzer = ResponseIntelligence()
        result = analyzer.analyze(
            baseline_text="OK",
            payload_text="Internal Server Error",
            status_code_baseline=200,
            status_code_payload=500,
        )
        assert result["behavior_change"] is True
        assert result["is_anomalous"] is True

    def test_generic_error_detection(self):
        from core.response_intelligence import ResponseIntelligence
        analyzer = ResponseIntelligence()
        result = analyzer.analyze(
            baseline_text="Normal",
            payload_text="Internal Server Error - stack trace follows",
        )
        assert result["is_anomalous"] is True

    def test_detect_technology(self):
        from core.response_intelligence import ResponseIntelligence
        analyzer = ResponseIntelligence()
        detected = analyzer.detect_technology(
            "WordPress site with wp-content",
            headers={"X-Powered-By": "PHP/8.1"},
        )
        assert "php" in detected
        assert "wordpress" in detected

    def test_detect_technology_django(self):
        from core.response_intelligence import ResponseIntelligence
        analyzer = ResponseIntelligence()
        detected = analyzer.detect_technology(
            '<input name="csrfmiddlewaretoken" value="abc123">',
        )
        assert "python" in detected

    def test_confidence_boost_capped(self):
        from core.response_intelligence import ResponseIntelligence
        analyzer = ResponseIntelligence()
        result = analyzer.analyze(
            baseline_text="",
            payload_text=(
                "You have an error in your SQL syntax\n"
                "mysql_fetch_array()\n"
                "Warning: mysql_query()\n"
                "File: /home/app/db.php\n"
                "root:x:0:0:\n"
                "-----BEGIN RSA PRIVATE KEY-----\n"
                "password = secret123\n"
            ),
            technology="mysql",
            status_code_baseline=200,
            status_code_payload=500,
        )
        assert result["confidence_boost"] <= 50

    def test_no_false_positive_same_content(self):
        from core.response_intelligence import ResponseIntelligence
        analyzer = ResponseIntelligence()
        text = "Some normal page content without errors"
        result = analyzer.analyze(
            baseline_text=text,
            payload_text=text,
        )
        assert result["is_anomalous"] is False
        assert result["confidence_boost"] == 0


# ── New Exploit Modules ─────────────────────────────────────────


class TestDeserializationExploiter:
    """Test deserialization exploiter."""

    def test_import(self):
        from exploits.advanced.deserialization_exploiter import DeserializationExploiter
        assert DeserializationExploiter is not None

    def test_instantiate(self):
        from exploits.advanced.deserialization_exploiter import DeserializationExploiter
        exp = DeserializationExploiter()
        assert hasattr(exp, "run")
        assert hasattr(exp, "findings")

    def test_check_deserialization_java(self):
        from exploits.advanced.deserialization_exploiter import DeserializationExploiter
        exp = DeserializationExploiter()
        result = exp._check_deserialization(
            "Normal response",
            "java.lang.ClassNotFoundException: malicious.Class",
        )
        assert result["detected"] is True
        assert result["type"] == "java"

    def test_check_deserialization_php(self):
        from exploits.advanced.deserialization_exploiter import DeserializationExploiter
        exp = DeserializationExploiter()
        result = exp._check_deserialization(
            "Normal response",
            "PHP Fatal error: unserialize() failed",
        )
        assert result["detected"] is True
        assert result["type"] == "php"

    def test_check_deserialization_clean(self):
        from exploits.advanced.deserialization_exploiter import DeserializationExploiter
        exp = DeserializationExploiter()
        result = exp._check_deserialization(
            "Normal response",
            "Normal response with different content",
        )
        assert result["detected"] is False


class TestAPIKeyExposureExploiter:
    """Test API key exposure scanner."""

    def test_import(self):
        from exploits.advanced.api_key_exposure_exploiter import APIKeyExposureExploiter
        assert APIKeyExposureExploiter is not None

    def test_instantiate(self):
        from exploits.advanced.api_key_exposure_exploiter import APIKeyExposureExploiter
        exp = APIKeyExposureExploiter()
        assert hasattr(exp, "run")

    def test_is_likely_real_filters_placeholders(self):
        from exploits.advanced.api_key_exposure_exploiter import APIKeyExposureExploiter
        assert APIKeyExposureExploiter._is_likely_real("REPLACE_ME_KEY", "generic") is False
        assert APIKeyExposureExploiter._is_likely_real("xxxxxxxxxxxxxxxx", "generic") is False
        assert APIKeyExposureExploiter._is_likely_real("short", "generic") is False

    def test_is_likely_real_accepts_valid(self):
        from exploits.advanced.api_key_exposure_exploiter import APIKeyExposureExploiter
        assert APIKeyExposureExploiter._is_likely_real(
            "sk_live_abcdefghijklmnop123456", "stripe"
        ) is True

    def test_redact(self):
        from exploits.advanced.api_key_exposure_exploiter import APIKeyExposureExploiter
        result = APIKeyExposureExploiter._redact("AKIA1234567890ABCDEF")
        assert result.startswith("AKIA")
        assert result.endswith("CDEF")
        assert "*" in result

    def test_redact_short(self):
        from exploits.advanced.api_key_exposure_exploiter import APIKeyExposureExploiter
        result = APIKeyExposureExploiter._redact("secret")
        assert result.startswith("se")
        assert len(result) == len("secret")


class TestHTTP2DesyncExploiter:
    """Test HTTP/2 desync exploiter."""

    def test_import(self):
        from exploits.advanced.http2_desync_exploiter import HTTP2DesyncExploiter
        assert HTTP2DesyncExploiter is not None

    def test_instantiate(self):
        from exploits.advanced.http2_desync_exploiter import HTTP2DesyncExploiter
        exp = HTTP2DesyncExploiter()
        assert hasattr(exp, "run")

    def test_check_desync_indicators_400(self):
        from exploits.advanced.http2_desync_exploiter import HTTP2DesyncExploiter
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "Bad Request"
        assert HTTP2DesyncExploiter._check_desync_indicators(mock_resp) is True

    def test_check_desync_indicators_normal(self):
        from exploits.advanced.http2_desync_exploiter import HTTP2DesyncExploiter
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "Normal response page content"
        assert HTTP2DesyncExploiter._check_desync_indicators(mock_resp) is False


# ── Enhanced Evidence Proof Descriptions ─────────────────────────


class TestHydraProofDescriptions:
    """Test new proof description types for Hydra features."""

    def test_deserialization_proof(self):
        from core.evidence import build_proof_description
        desc = build_proof_description("Insecure Deserialization", {
            "deserialization_type": "java",
        })
        assert "deserialization" in desc.lower()
        assert "java" in desc.lower()

    def test_api_key_proof(self):
        from core.evidence import build_proof_description
        desc = build_proof_description("API Key Exposure", {
            "key_type": "aws_access_key",
            "description": "AWS Access Key ID",
            "match_count": 2,
        })
        assert "API key" in desc
        assert "AWS" in desc

    def test_desync_proof(self):
        from core.evidence import build_proof_description
        desc = build_proof_description("HTTP/2 Desynchronization", {
            "desync_type": "H2.CL",
        })
        assert "desync" in desc.lower()
        assert "H2.CL" in desc

    def test_bayesian_proof(self):
        from core.evidence import build_proof_description
        desc = build_proof_description("SQLi", {
            "bayesian_posterior": 0.95,
            "signals_used": 4,
        })
        assert "Bayesian" in desc
        assert "95.0%" in desc

    def test_attack_chain_proof(self):
        from core.evidence import build_proof_description
        desc = build_proof_description("SSRF", {
            "attack_chain": True,
            "chain_description": "SSRF to Internal RCE",
            "chain_impact": 10,
        })
        assert "attack chain" in desc.lower()
        assert "SSRF" in desc


# ── Base Exploiter Hydra Integration ─────────────────────────────


class TestBaseExploiterHydra:
    """Test Hydra features integrated into BaseExploiter."""

    def test_smart_selector_present(self):
        from exploits.base_exploiter import BaseExploiter
        # Can't instantiate abstract, but check the class imports
        assert hasattr(BaseExploiter, '_prioritize_payloads')

    def test_response_intel_present(self):
        from exploits.base_exploiter import BaseExploiter
        assert hasattr(BaseExploiter, '_analyze_response_intelligence')

    def test_record_payload_success_present(self):
        from exploits.base_exploiter import BaseExploiter
        assert hasattr(BaseExploiter, '_record_payload_success')

    def test_concrete_exploiter_has_hydra_methods(self):
        """A concrete exploiter should inherit all Hydra methods."""
        from exploits.advanced.deserialization_exploiter import DeserializationExploiter
        exp = DeserializationExploiter()
        assert hasattr(exp, 'smart_selector')
        assert hasattr(exp, 'response_intel')
        assert hasattr(exp, '_smart_selection')
        assert hasattr(exp, '_response_intelligence')

    def test_prioritize_payloads_disabled(self):
        """When smart selection is disabled, returns original list."""
        from exploits.advanced.deserialization_exploiter import DeserializationExploiter
        exp = DeserializationExploiter()
        exp._smart_selection = False
        payloads = ["p1", "p2", "p3"]
        result = exp._prioritize_payloads(payloads)
        assert result == payloads

    def test_analyze_response_disabled(self):
        """When response intelligence is disabled, returns minimal result."""
        from exploits.advanced.deserialization_exploiter import DeserializationExploiter
        exp = DeserializationExploiter()
        exp._response_intelligence = False
        result = exp._analyze_response_intelligence("baseline", "payload")
        assert result["is_anomalous"] is False
        assert result["confidence_boost"] == 0


# ── Engine Integration ─────────────────────────────────────────


class TestEngineHydraIntegration:
    """Test Hydra phases integrated into ScanEngine."""

    def test_engine_loads_new_modules(self):
        """Engine should include deserialization, api_key_exposure, http2_desync."""
        from core.engine import ScanEngine
        with patch("core.engine.init_db"):
            engine = ScanEngine(enable_integrations=False)
        modules = engine._load_all_modules()
        assert "deserialization" in modules
        assert "api_key_exposure" in modules
        assert "http2_desync" in modules

    def test_engine_advanced_category_includes_new(self):
        """Advanced category should include new modules."""
        from core.engine import ScanEngine
        with patch("core.engine.init_db"):
            engine = ScanEngine(enable_integrations=False)
        modules = engine._get_modules("category", category="advanced")
        module_names = [name for name, _ in modules]
        assert "deserialization" in module_names
        assert "api_key_exposure" in module_names
        assert "http2_desync" in module_names

    def test_hydra_depth_preset_loaded(self):
        """Engine with hydra depth should load hydra preset."""
        from core.engine import ScanEngine
        with patch("core.engine.init_db"):
            engine = ScanEngine(enable_integrations=False, depth="hydra")
        assert engine.depth == "hydra"
        assert engine.depth_preset.get("smart_payload_selection") is True
        assert engine.depth_preset.get("bayesian_scoring") is True
        assert engine.depth_preset.get("attack_chain_correlation") is True

    def test_extract_evidence_signals_basic(self):
        """Test signal extraction from finding evidence."""
        from core.engine import ScanEngine
        finding = {
            "verification_status": "confirmed",
            "evidence": {
                "proof_data": {
                    "error_pattern": "SQL syntax error",
                    "baseline_missing_pattern": True,
                },
            },
        }
        signals = ScanEngine._extract_evidence_signals(finding)
        assert signals.get("error_pattern") is True
        assert signals.get("baseline_clean") is True
        assert signals.get("retest_confirmed") is True

    def test_extract_evidence_signals_empty(self):
        """Empty evidence should return empty signals."""
        from core.engine import ScanEngine
        signals = ScanEngine._extract_evidence_signals({})
        assert signals == {}

    def test_extract_evidence_signals_timing(self):
        from core.engine import ScanEngine
        finding = {
            "evidence": {
                "proof_data": {
                    "timing_diff": 5.0,
                    "entropy_delta": 0.5,
                },
            },
        }
        signals = ScanEngine._extract_evidence_signals(finding)
        assert signals.get("timing_confirmed") is True
        assert signals.get("entropy_anomaly") is True

    def test_extract_evidence_signals_chain(self):
        from core.engine import ScanEngine
        finding = {
            "attack_chains": [{"chain_id": "chain_1"}],
            "evidence": {"proof_data": {}},
        }
        signals = ScanEngine._extract_evidence_signals(finding)
        assert signals.get("chain_correlated") is True


# ── Payload Files ─────────────────────────────────────────────────


class TestHydraPayloads:
    """Verify new and enhanced payload files."""

    def test_deserialization_probes_exist(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "payloads", "deserialization", "probes.txt"
        )
        assert os.path.exists(path)
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        assert len(lines) >= 8

    def test_deserialization_gadgets_exist(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "payloads", "deserialization", "gadgets.txt"
        )
        assert os.path.exists(path)
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        assert len(lines) >= 5

    def test_waf_bypass_enhanced(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "payloads", "sqli", "waf_bypass.txt"
        )
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        # Should have more than v7.0's 37 lines
        assert len(lines) >= 45

    def test_polyglot_enhanced(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "payloads", "xss", "polyglot.txt"
        )
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        # Should have more than v7.0's 2 lines
        assert len(lines) >= 10
