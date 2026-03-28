"""Tests for VenomStrike v4.0 Quantum Edition features.

Covers:
- Quantum config settings & depth preset
- Triple-marker confirmation pipeline
- Entropy-based anomaly detection
- Cross-correlation verification
- Statistical confidence scoring
- Quantum evidence chain metadata
- Quantum proof descriptions
"""
import os
import sys
import math
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Config: Quantum settings ──────────────────────────────────────


class TestQuantumConfig:
    """Verify Quantum v4.0 config additions."""

    def test_version_is_4(self):
        import config
        assert config.VERSION == "6.0.0"

    def test_codename_is_quantum(self):
        import config
        assert config.CODENAME == "Viper"

    def test_quantum_depth_preset_exists(self):
        import config
        assert "quantum" in config.DEPTH_PRESETS

    def test_quantum_depth_is_valid(self):
        import config
        assert "quantum" in config._VALID_DEPTHS

    def test_quantum_preset_has_required_keys(self):
        import config
        preset = config.DEPTH_PRESETS["quantum"]
        for key in ("crawl_depth", "max_crawl_pages", "dir_brute_limit",
                     "api_brute_limit", "payload_limit", "validation_attempts",
                     "min_confidence"):
            assert key in preset, f"Missing key: {key}"

    def test_quantum_preset_deeper_than_full(self):
        import config
        q = config.DEPTH_PRESETS["quantum"]
        f = config.DEPTH_PRESETS["full"]
        assert q["crawl_depth"] > f["crawl_depth"]
        assert q["max_crawl_pages"] > f["max_crawl_pages"]
        assert q["validation_attempts"] > f["validation_attempts"]

    def test_quantum_preset_has_quantum_flags(self):
        import config
        preset = config.DEPTH_PRESETS["quantum"]
        assert preset.get("cross_correlation") is True
        assert preset.get("entropy_analysis") is True
        assert preset.get("triple_confirm") is True
        assert preset.get("statistical_confidence") is True

    def test_quantum_config_keys_exist(self):
        import config
        assert hasattr(config, "QUANTUM_CROSS_CORRELATION")
        assert hasattr(config, "QUANTUM_ENTROPY_THRESHOLD")
        assert hasattr(config, "QUANTUM_TRIPLE_CONFIRM")
        assert hasattr(config, "QUANTUM_STATISTICAL_MIN_SAMPLES")

    def test_quantum_entropy_threshold_range(self):
        import config
        assert 0.0 <= config.QUANTUM_ENTROPY_THRESHOLD <= 1.0

    def test_quantum_stat_min_samples_range(self):
        import config
        assert 3 <= config.QUANTUM_STATISTICAL_MIN_SAMPLES <= 20

    def test_depth_presets_ordering_includes_quantum(self):
        """Quantum should have higher crawl_depth than all other levels."""
        import config
        levels = ["quick", "standard", "deep", "full", "quantum"]
        for i in range(len(levels) - 1):
            a = config.DEPTH_PRESETS[levels[i]]
            b = config.DEPTH_PRESETS[levels[i + 1]]
            assert a["crawl_depth"] <= b["crawl_depth"]
            assert a["max_crawl_pages"] <= b["max_crawl_pages"]

    def test_user_agent_contains_quantum(self):
        import config
        assert "Viper" in config.DEFAULT_USER_AGENT or "6.0" in config.DEFAULT_USER_AGENT


# ── Entropy-based anomaly detection ───────────────────────────────


class TestEntropyDetection:
    """Verify the entropy-based anomaly detection in ResultValidator."""

    def test_entropy_of_empty_string(self):
        import requests
        from core.validator import ResultValidator
        session = MagicMock(spec=requests.Session)
        validator = ResultValidator(session)
        assert validator.calculate_response_entropy("") == 0.0

    def test_entropy_of_uniform_string(self):
        """A string of identical characters should have zero entropy."""
        import requests
        from core.validator import ResultValidator
        session = MagicMock(spec=requests.Session)
        validator = ResultValidator(session)
        entropy = validator.calculate_response_entropy("aaaaaaaaaa")
        assert entropy == 0.0

    def test_entropy_of_varied_string(self):
        """A string with varied characters should have positive entropy."""
        import requests
        from core.validator import ResultValidator
        session = MagicMock(spec=requests.Session)
        validator = ResultValidator(session)
        entropy = validator.calculate_response_entropy("abcdefghij")
        assert entropy > 0.0
        # 10 unique chars → entropy ≈ log2(10) ≈ 3.32
        assert entropy > 3.0

    def test_entropy_anomaly_detected(self):
        """Significant entropy shift should be flagged."""
        import requests
        from core.validator import ResultValidator
        session = MagicMock(spec=requests.Session)
        validator = ResultValidator(session)
        baseline = "Normal page content " * 20
        payload = "ERROR: SQL syntax error near 'DROP TABLE' at line 1. Stack trace: ..."
        result = validator.detect_entropy_anomaly(baseline, payload)
        assert "is_anomaly" in result
        assert "entropy_delta" in result
        assert "baseline_entropy" in result
        assert "payload_entropy" in result

    def test_entropy_no_anomaly_similar_content(self):
        """Similar responses should not flag an anomaly."""
        import requests
        from core.validator import ResultValidator
        session = MagicMock(spec=requests.Session)
        validator = ResultValidator(session)
        baseline = "Hello world this is a normal page"
        payload = "Hello world this is a normal page"
        result = validator.detect_entropy_anomaly(baseline, payload, threshold=0.5)
        assert result["is_anomaly"] is False
        assert result["entropy_delta"] == 0.0

    def test_entropy_anomaly_custom_threshold(self):
        """Custom threshold should be respected."""
        import requests
        from core.validator import ResultValidator
        session = MagicMock(spec=requests.Session)
        validator = ResultValidator(session)
        result = validator.detect_entropy_anomaly("aaa", "abcdefg", threshold=0.01)
        assert result["threshold"] == 0.01


# ── Cross-correlation verification ────────────────────────────────


class TestCrossCorrelation:
    """Verify cross-correlation finding boosting."""

    def test_correlated_findings_boosted(self):
        """Findings of same type on same endpoint should be boosted."""
        import requests
        from core.validator import ResultValidator
        session = MagicMock(spec=requests.Session)
        validator = ResultValidator(session)

        findings = [
            {"vuln_type": "SQLi", "url": "http://example.com/page?id=1", "confidence": 70},
            {"vuln_type": "SQLi", "url": "http://example.com/page?name=test", "confidence": 70},
        ]
        result = validator.cross_correlate_findings(findings, min_cluster=2)
        assert result[0]["cross_correlated"] is True
        assert result[1]["cross_correlated"] is True
        assert result[0]["confidence"] > 70
        assert result[0]["correlation_cluster_size"] == 2

    def test_uncorrelated_findings_not_boosted(self):
        """Findings of different types should not be cross-correlated."""
        import requests
        from core.validator import ResultValidator
        session = MagicMock(spec=requests.Session)
        validator = ResultValidator(session)

        findings = [
            {"vuln_type": "SQLi", "url": "http://example.com/page?id=1", "confidence": 70},
            {"vuln_type": "XSS", "url": "http://example.com/page?name=test", "confidence": 70},
        ]
        result = validator.cross_correlate_findings(findings, min_cluster=2)
        assert result[0]["cross_correlated"] is False
        assert result[1]["cross_correlated"] is False
        assert result[0]["confidence"] == 70

    def test_single_finding_not_boosted(self):
        """A lone finding should not be boosted."""
        import requests
        from core.validator import ResultValidator
        session = MagicMock(spec=requests.Session)
        validator = ResultValidator(session)

        findings = [
            {"vuln_type": "SQLi", "url": "http://example.com/page?id=1", "confidence": 70},
        ]
        result = validator.cross_correlate_findings(findings, min_cluster=2)
        assert result[0]["cross_correlated"] is False
        assert result[0]["confidence"] == 70

    def test_large_cluster_bigger_boost(self):
        """Larger clusters should get more confidence boost."""
        import requests
        from core.validator import ResultValidator
        session = MagicMock(spec=requests.Session)
        validator = ResultValidator(session)

        findings = [
            {"vuln_type": "SQLi", "url": "http://example.com/page?id=1", "confidence": 70},
            {"vuln_type": "SQLi", "url": "http://example.com/page?name=test", "confidence": 70},
            {"vuln_type": "SQLi", "url": "http://example.com/page?q=search", "confidence": 70},
        ]
        result = validator.cross_correlate_findings(findings, min_cluster=2)
        assert result[0]["correlation_cluster_size"] == 3
        assert result[0]["confidence"] == 80  # 70 + min(10, (3-1)*5) = 80

    def test_confidence_capped_at_100(self):
        """Boosted confidence should not exceed 100."""
        import requests
        from core.validator import ResultValidator
        session = MagicMock(spec=requests.Session)
        validator = ResultValidator(session)

        findings = [
            {"vuln_type": "SQLi", "url": "http://example.com/page?id=1", "confidence": 98},
            {"vuln_type": "SQLi", "url": "http://example.com/page?name=test", "confidence": 98},
        ]
        result = validator.cross_correlate_findings(findings, min_cluster=2)
        assert result[0]["confidence"] <= 100

    def test_empty_findings_handled(self):
        """Empty findings list should be handled gracefully."""
        import requests
        from core.validator import ResultValidator
        session = MagicMock(spec=requests.Session)
        validator = ResultValidator(session)
        result = validator.cross_correlate_findings([], min_cluster=2)
        assert result == []

    def test_cross_correlation_disabled_via_config(self):
        """When disabled, findings should not be modified."""
        import requests
        from core.validator import ResultValidator
        session = MagicMock(spec=requests.Session)
        validator = ResultValidator(session)
        findings = [
            {"vuln_type": "SQLi", "url": "http://example.com/page?id=1", "confidence": 70},
            {"vuln_type": "SQLi", "url": "http://example.com/page?name=test", "confidence": 70},
        ]
        with patch("core.validator.QUANTUM_CROSS_CORRELATION", False):
            result = validator.cross_correlate_findings(findings, min_cluster=2)
            assert "cross_correlated" not in result[0]


# ── Statistical confidence ────────────────────────────────────────


class TestStatisticalConfidence:
    """Verify z-score based statistical confidence."""

    def test_significant_measurements(self):
        """Clearly high values should produce significant z-scores."""
        import requests
        from core.validator import ResultValidator
        session = MagicMock(spec=requests.Session)
        validator = ResultValidator(session)
        # Baseline mean ~0.2s, measurements all ~5.2s (timing injection)
        measurements = [5.1, 5.3, 5.2, 5.0, 5.4]
        result = validator.statistical_confidence(measurements, expected_shift=5.0, baseline_mean=0.2)
        assert result["p_significant"] is True
        assert result["statistical_confidence"] > 50
        assert result["sample_count"] == 5

    def test_insignificant_measurements(self):
        """Measurements near baseline should not be significant."""
        import requests
        from core.validator import ResultValidator
        session = MagicMock(spec=requests.Session)
        validator = ResultValidator(session)
        measurements = [0.21, 0.19, 0.22, 0.20, 0.18]
        result = validator.statistical_confidence(measurements, expected_shift=5.0, baseline_mean=0.2)
        assert result["p_significant"] is False

    def test_too_few_samples(self):
        """Below min samples should return zero confidence."""
        import requests
        from core.validator import ResultValidator
        session = MagicMock(spec=requests.Session)
        validator = ResultValidator(session)
        measurements = [5.0, 5.1]  # Only 2, default min is 5
        result = validator.statistical_confidence(measurements, expected_shift=5.0)
        assert result["statistical_confidence"] == 0
        assert result["sample_count"] == 2

    def test_zero_variance_with_shift(self):
        """Zero variance (all same) with shift should show high confidence."""
        import requests
        from core.validator import ResultValidator
        session = MagicMock(spec=requests.Session)
        validator = ResultValidator(session)
        measurements = [5.0, 5.0, 5.0, 5.0, 5.0]
        result = validator.statistical_confidence(measurements, expected_shift=5.0, baseline_mean=0.0)
        assert result["statistical_confidence"] > 50

    def test_result_keys(self):
        """Result should contain all expected keys."""
        import requests
        from core.validator import ResultValidator
        session = MagicMock(spec=requests.Session)
        validator = ResultValidator(session)
        result = validator.statistical_confidence([1, 2, 3, 4, 5], expected_shift=5.0)
        for key in ("z_score", "p_significant", "mean", "stdev",
                     "sample_count", "statistical_confidence"):
            assert key in result, f"Missing key: {key}"


# ── Triple-marker confirmation ────────────────────────────────────


class TestTripleConfirmation:
    """Verify the Quantum triple-marker confirmation pipeline."""

    def test_triple_all_match_baseline_clean(self):
        """All three markers match + clean baseline = confirmed with 25-point boost."""
        import requests
        from core.confirmation import InjectionConfirmer

        session = MagicMock(spec=requests.Session)
        confirmer = InjectionConfirmer(session)

        mock_resp = MagicMock(spec=requests.Response)
        mock_resp.text = ""

        def inject_func(marker):
            mock_resp.text = f"reflected: {marker}"
            return mock_resp

        def check_func(resp, marker):
            return marker in resp.text

        baseline_resp = MagicMock(spec=requests.Response)
        baseline_resp.text = "clean page"

        result = confirmer.confirm_triple(
            inject_func=inject_func,
            check_func=check_func,
            baseline_func=lambda: baseline_resp,
        )
        assert result["confirmed"] is True
        assert result["probe_matched"] is True
        assert result["confirm_matched"] is True
        assert result["triple_matched"] is True
        assert result["baseline_clean"] is True
        assert result["confidence_boost"] == 25
        assert result["verification_level"] == "quantum_triple"

    def test_triple_two_match(self):
        """Two markers match + clean baseline = confirmed with 15-point boost."""
        import requests
        from core.confirmation import InjectionConfirmer

        session = MagicMock(spec=requests.Session)
        confirmer = InjectionConfirmer(session)

        call_count = [0]
        mock_resp = MagicMock(spec=requests.Response)

        def inject_func(marker):
            call_count[0] += 1
            if call_count[0] <= 2:
                mock_resp.text = f"reflected: {marker}"
            else:
                mock_resp.text = "no reflection"
            return mock_resp

        def check_func(resp, marker):
            return marker in resp.text

        baseline_resp = MagicMock(spec=requests.Response)
        baseline_resp.text = "clean page"

        result = confirmer.confirm_triple(
            inject_func=inject_func,
            check_func=check_func,
            baseline_func=lambda: baseline_resp,
        )
        assert result["confirmed"] is True
        assert result["confidence_boost"] == 15

    def test_triple_probe_only(self):
        """Only probe matches = not confirmed, 0 boost."""
        import requests
        from core.confirmation import InjectionConfirmer

        session = MagicMock(spec=requests.Session)
        confirmer = InjectionConfirmer(session)

        call_count = [0]
        mock_resp = MagicMock(spec=requests.Response)

        def inject_func(marker):
            call_count[0] += 1
            if call_count[0] == 1:
                mock_resp.text = f"reflected: {marker}"
            else:
                mock_resp.text = "no reflection"
            return mock_resp

        def check_func(resp, marker):
            return marker in resp.text

        result = confirmer.confirm_triple(
            inject_func=inject_func,
            check_func=check_func,
        )
        assert result["confirmed"] is False
        assert result["confidence_boost"] == 0

    def test_triple_dirty_baseline(self):
        """All three match but dirty baseline = reduced boost."""
        import requests
        from core.confirmation import InjectionConfirmer

        session = MagicMock(spec=requests.Session)
        confirmer = InjectionConfirmer(session)

        markers_seen = []
        mock_resp = MagicMock(spec=requests.Response)

        def inject_func(marker):
            markers_seen.append(marker)
            mock_resp.text = f"reflected: {marker}"
            return mock_resp

        def check_func(resp, marker):
            return marker in resp.text

        baseline_resp = MagicMock(spec=requests.Response)

        def baseline_func():
            # Baseline also "matches" the check — it's dirty
            baseline_resp.text = f"reflected: {markers_seen[0]}" if markers_seen else "clean"
            return baseline_resp

        result = confirmer.confirm_triple(
            inject_func=inject_func,
            check_func=check_func,
            baseline_func=baseline_func,
        )
        assert result["baseline_clean"] is False
        assert result["confidence_boost"] == 5  # Reduced

    def test_triple_fallback_when_disabled(self):
        """When QUANTUM_TRIPLE_CONFIRM is False, fallback to dual."""
        import requests
        from core.confirmation import InjectionConfirmer

        session = MagicMock(spec=requests.Session)
        confirmer = InjectionConfirmer(session)

        mock_resp = MagicMock(spec=requests.Response)

        def inject_func(marker):
            mock_resp.text = f"reflected: {marker}"
            return mock_resp

        def check_func(resp, marker):
            return marker in resp.text

        with patch("core.confirmation.QUANTUM_TRIPLE_CONFIRM", False):
            result = confirmer.confirm_triple(
                inject_func=inject_func,
                check_func=check_func,
            )
            assert result["verification_level"] == "dual"

    def test_triple_has_three_markers(self):
        """Triple confirmation should generate 3 distinct markers."""
        import requests
        from core.confirmation import InjectionConfirmer

        session = MagicMock(spec=requests.Session)
        confirmer = InjectionConfirmer(session)

        mock_resp = MagicMock(spec=requests.Response)
        mock_resp.text = "no match"

        result = confirmer.confirm_triple(
            inject_func=lambda marker: mock_resp,
            check_func=lambda resp, marker: False,
        )
        markers = result.get("markers", ())
        assert len(markers) == 3
        assert len(set(markers)) == 3  # All unique


# ── Evidence quantum fields ───────────────────────────────────────


class TestQuantumEvidence:
    """Verify quantum metadata fields on EvidencePackage."""

    def test_evidence_has_verification_chain(self):
        from core.evidence import EvidencePackage
        ep = EvidencePackage()
        assert ep.verification_chain == []

    def test_evidence_has_entropy_analysis(self):
        from core.evidence import EvidencePackage
        ep = EvidencePackage()
        assert ep.entropy_analysis == {}

    def test_evidence_has_cross_correlation(self):
        from core.evidence import EvidencePackage
        ep = EvidencePackage()
        assert ep.cross_correlation == {}

    def test_evidence_has_statistical_summary(self):
        from core.evidence import EvidencePackage
        ep = EvidencePackage()
        assert ep.statistical_summary == {}

    def test_to_dict_includes_verification_chain(self):
        from core.evidence import EvidencePackage
        ep = EvidencePackage(
            verification_chain=[
                {"step": "probe", "result": True, "timestamp": 1234567890.0},
            ]
        )
        d = ep.to_dict()
        assert "verification_chain" in d
        assert len(d["verification_chain"]) == 1

    def test_to_dict_includes_entropy_analysis(self):
        from core.evidence import EvidencePackage
        ep = EvidencePackage(
            entropy_analysis={"baseline_entropy": 3.2, "payload_entropy": 4.1, "delta": 0.9}
        )
        d = ep.to_dict()
        assert "entropy_analysis" in d
        assert d["entropy_analysis"]["delta"] == 0.9

    def test_to_dict_includes_cross_correlation(self):
        from core.evidence import EvidencePackage
        ep = EvidencePackage(
            cross_correlation={"correlated": True, "cluster_size": 3}
        )
        d = ep.to_dict()
        assert d["cross_correlation"]["cluster_size"] == 3

    def test_to_dict_includes_statistical_summary(self):
        from core.evidence import EvidencePackage
        ep = EvidencePackage(
            statistical_summary={"z_score": 3.5, "p_significant": True}
        )
        d = ep.to_dict()
        assert d["statistical_summary"]["z_score"] == 3.5

    def test_to_dict_omits_empty_quantum_fields(self):
        from core.evidence import EvidencePackage
        ep = EvidencePackage(vuln_type="XSS")
        d = ep.to_dict()
        assert "verification_chain" not in d
        assert "entropy_analysis" not in d
        assert "cross_correlation" not in d
        assert "statistical_summary" not in d


# ── Quantum proof descriptions ────────────────────────────────────


class TestQuantumProofDescriptions:
    """Verify proof descriptions for quantum-specific evidence types."""

    def test_triple_confirmation_proof(self):
        from core.evidence import build_proof_description
        proof = build_proof_description("SQLi", {
            "triple_confirmation": True,
        })
        assert "triple" in proof.lower()
        assert "three" in proof.lower() or "3" in proof

    def test_entropy_proof(self):
        from core.evidence import build_proof_description
        proof = build_proof_description("SQLi", {
            "entropy_delta": 0.85,
            "baseline_entropy": 3.2,
            "payload_entropy": 4.05,
        })
        assert "entropy" in proof.lower()
        assert "0.85" in proof

    def test_cross_correlation_proof(self):
        from core.evidence import build_proof_description
        proof = build_proof_description("SQLi", {
            "cross_correlated": True,
            "cluster_size": 3,
        })
        assert "cross-correlation" in proof.lower() or "corroborating" in proof.lower()
        assert "3" in proof

    def test_z_score_proof(self):
        from core.evidence import build_proof_description
        proof = build_proof_description("SQLi Blind", {
            "z_score": 3.45,
            "p_significant": True,
            "sample_count": 5,
        })
        assert "z-score" in proof.lower() or "statistical" in proof.lower()
        assert "3.45" in proof

    def test_z_score_not_significant_proof(self):
        from core.evidence import build_proof_description
        proof = build_proof_description("SQLi Blind", {
            "z_score": 1.2,
            "p_significant": False,
            "sample_count": 5,
        })
        assert ">= 0.05" in proof or "not" in proof.lower()
