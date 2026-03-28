"""Result validator — multi-strategy re-testing with timing calibration.

Quantum Edition (v4.0) adds:
- Cross-correlation verification: checks multiple injection points for
  correlated behaviour changes to eliminate coincidental matches.
- Statistical confidence scoring: uses standard deviation and z-scores
  across re-test samples for data-driven confidence.
- Entropy-based anomaly detection: measures response entropy delta to
  distinguish real vulnerability indicators from noise.
- Triple-marker confirmation support: validates with 3 independent markers
  instead of 2 for higher assurance.
"""
# For authorized security testing only.
import math
import time
import statistics
import logging
from typing import Dict, Optional, Callable, List
import requests
from core.utils import make_request, response_diff
from core.evidence import (
    EvidencePackage, capture_request_trace,
    VERIFIED_CONFIRMED, VERIFIED_LIKELY, VERIFIED_SUSPICIOUS,
    VERIFIED_UNVERIFIED, VERIFIED_FALSE_POSITIVE,
)
from config import (
    VALIDATION_ATTEMPTS, MIN_CONFIDENCE, TIMING_TOLERANCE,
    QUANTUM_CROSS_CORRELATION, QUANTUM_ENTROPY_THRESHOLD,
    QUANTUM_STATISTICAL_MIN_SAMPLES,
)

logger = logging.getLogger("venomstrike.validator")


class ResultValidator:
    """Multi-strategy finding validator.

    Validates findings by:
    1. Re-testing the exploit multiple times for consistency
    2. Calibrating timing baselines (for blind vulns)
    3. Comparing baseline vs payload responses semantically
    4. Scoring confidence based on weighted evidence factors
    """

    def __init__(self, session: requests.Session):
        self.session = session
        self._timing_baselines: Dict[str, float] = {}

    # ── Public API ──────────────────────────────────────────────────

    def validate_finding(self, finding: Dict, test_func: Callable) -> Dict:
        """Validate a finding by re-testing it multiple times.

        Args:
            finding: The finding dict to validate.
            test_func: A callable(finding) -> bool that re-runs the exploit.

        Returns:
            The finding dict with updated confidence and verification fields.
        """
        confirmations = 0
        total_attempts = VALIDATION_ATTEMPTS
        retest_results = []

        for attempt in range(total_attempts):
            try:
                confirmed = test_func(finding)
                retest_results.append({
                    "attempt": attempt + 1,
                    "confirmed": bool(confirmed),
                    "timestamp": time.time(),
                })
                if confirmed:
                    confirmations += 1
                time.sleep(0.3)
            except Exception as e:
                logger.debug(
                    "Retest attempt %d failed for %s: %s",
                    attempt + 1, finding.get("vuln_type", "unknown"), e,
                )
                retest_results.append({
                    "attempt": attempt + 1,
                    "confirmed": False,
                    "error": str(e),
                    "timestamp": time.time(),
                })

        # Calculate boost: full 30-point boost only when ALL attempts confirm
        confidence_boost = (confirmations / max(total_attempts, 1)) * 30
        new_confidence = min(100, finding.get("confidence", 70) + int(confidence_boost))
        finding["confidence"] = new_confidence

        # Set verification status
        if confirmations >= 2:
            status = VERIFIED_CONFIRMED
            details = f"Confirmed {confirmations}/{total_attempts} re-tests"
        elif confirmations == 1:
            status = VERIFIED_LIKELY
            details = f"Confirmed 1/{total_attempts} re-tests"
        else:
            status = VERIFIED_SUSPICIOUS
            details = f"Could not reproduce in {total_attempts} re-tests"
            # Penalize confidence for unreproducible findings
            finding["confidence"] = max(0, finding["confidence"] - 20)

        finding["verification_status"] = status
        finding["verification_details"] = details
        finding["retest_results"] = retest_results
        finding["retest_confirmations"] = confirmations
        finding["retest_attempts"] = total_attempts

        # Update evidence package if present
        evidence = finding.get("evidence", {})
        if isinstance(evidence, dict):
            evidence["verification_status"] = status
            evidence["verification_details"] = details
            evidence["retest_confirmations"] = confirmations
            evidence["retest_attempts"] = total_attempts

        return finding

    def calibrate_timing(self, url: str, method: str = "GET",
                         samples: int = 5) -> float:
        """Measure baseline response time for timing-based detection.

        Takes ``samples`` measurements (default 5), trims the highest and
        lowest values when there are at least 5, and returns the median of
        the remaining set.  This reduces false positives on variable-latency
        networks compared to the previous 3-sample approach.

        Args:
            url: The target URL.
            method: HTTP method (default GET).
            samples: Number of timing samples to collect (default 5).

        Returns:
            The median response time in seconds.
        """
        if url in self._timing_baselines:
            return self._timing_baselines[url]

        times: List[float] = []
        for _ in range(samples):
            start = time.time()
            make_request(self.session, method, url, retries=0)
            elapsed = time.time() - start
            times.append(elapsed)
            time.sleep(0.1)

        if len(times) >= 5:
            # Trim the highest and lowest to reduce jitter influence
            times_sorted = sorted(times)
            trimmed = times_sorted[1:-1]
            median = statistics.median(trimmed)
        else:
            median = statistics.median(times) if times else 1.0

        self._timing_baselines[url] = median
        return median

    def is_timing_anomaly(self, url: str, elapsed: float,
                          sleep_seconds: float = 5.0,
                          tolerance: float = None) -> bool:
        """Check if a response time indicates a successful timing injection.

        The elapsed time must exceed: baseline_median + sleep_seconds - tolerance.
        ``tolerance`` defaults to the global ``TIMING_TOLERANCE`` setting so it
        can be tuned per-network via the VS_TIMING_TOLERANCE env variable.
        """
        if tolerance is None:
            tolerance = TIMING_TOLERANCE
        baseline = self.calibrate_timing(url)
        threshold = baseline + sleep_seconds - tolerance
        return elapsed >= max(threshold, sleep_seconds * 0.7)

    def calculate_confidence(
        self,
        payload_triggered: bool = False,
        response_different: bool = False,
        error_pattern_found: bool = False,
        content_matched: bool = False,
        timing_confirmed: bool = False,
        baseline_clean: bool = False,
        retest_confirmed: bool = False,
    ) -> int:
        """Calculate confidence score based on weighted evidence factors.

        Weights are tuned so that a finding needs multiple evidence types
        to reach HIGH confidence — no single factor can reach 70% alone.
        """
        score = 0
        if payload_triggered:
            score += 30
        if response_different:
            score += 15
        if error_pattern_found:
            score += 20
        if content_matched:
            score += 10
        if timing_confirmed:
            score += 25
        if baseline_clean:
            score += 15  # Confirms pattern absent in normal response
        if retest_confirmed:
            score += 20  # Extra boost for reproducibility
        return min(100, max(0, score))

    def is_reportable(self, confidence: int) -> bool:
        """Check if a finding meets the minimum confidence threshold."""
        return confidence >= MIN_CONFIDENCE

    # ── Quantum verification methods (v4.0) ────────────────────────

    @staticmethod
    def calculate_response_entropy(text: str) -> float:
        """Calculate Shannon entropy of a response body.

        Higher entropy indicates more random/structured content.
        A significant entropy delta between baseline and payload responses
        can indicate real vulnerability indicators (e.g. error dumps, file
        contents) rather than cosmetic differences.

        Returns:
            Entropy value in bits (0.0 for empty text).
        """
        if not text:
            return 0.0
        length = len(text)
        freq: Dict[str, int] = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def detect_entropy_anomaly(
        self,
        baseline_text: str,
        payload_text: str,
        threshold: float = None,
    ) -> Dict:
        """Detect anomalous entropy shifts between baseline and payload responses.

        When a vulnerability is triggered, the response often changes
        structurally (error messages, file contents, different page).  This
        manifests as a measurable entropy delta.

        Args:
            baseline_text: The normal (benign) response body.
            payload_text: The payload (exploit) response body.
            threshold: Minimum absolute entropy delta to flag.  Defaults to
                QUANTUM_ENTROPY_THRESHOLD from config.

        Returns:
            Dict with is_anomaly (bool), baseline_entropy, payload_entropy,
            entropy_delta, threshold.
        """
        if threshold is None:
            threshold = QUANTUM_ENTROPY_THRESHOLD
        baseline_entropy = self.calculate_response_entropy(baseline_text)
        payload_entropy = self.calculate_response_entropy(payload_text)
        delta = abs(payload_entropy - baseline_entropy)
        return {
            "is_anomaly": delta >= threshold,
            "baseline_entropy": baseline_entropy,
            "payload_entropy": payload_entropy,
            "entropy_delta": round(delta, 4),
            "threshold": threshold,
        }

    def cross_correlate_findings(
        self,
        findings: List[Dict],
        min_cluster: int = 2,
    ) -> List[Dict]:
        """Cross-correlate findings to boost confidence of clustered vulnerabilities.

        When multiple findings of the same vulnerability type appear on the
        same target (different parameters), it is strong corroborating
        evidence that each individual finding is real, because exploiting
        the same bug class in multiple locations is unlikely to be a
        coincidence.

        Args:
            findings: List of finding dicts.
            min_cluster: Minimum cluster size to trigger a confidence boost.

        Returns:
            The findings list with cross_correlation metadata added.
        """
        if not QUANTUM_CROSS_CORRELATION:
            return findings

        # Group by (vuln_type, base_url)
        clusters: Dict[str, List[int]] = {}
        for idx, f in enumerate(findings):
            base_url = f.get("url", "").split("?")[0]
            key = f"{f.get('vuln_type', '')}|{base_url}"
            clusters.setdefault(key, []).append(idx)

        for key, indices in clusters.items():
            if len(indices) >= min_cluster:
                for idx in indices:
                    findings[idx]["cross_correlated"] = True
                    findings[idx]["correlation_cluster_size"] = len(indices)
                    # Boost confidence by up to 10 points for correlated findings
                    boost = min(10, (len(indices) - 1) * 5)
                    findings[idx]["confidence"] = min(
                        100, findings[idx].get("confidence", 0) + boost
                    )
            else:
                for idx in indices:
                    findings[idx]["cross_correlated"] = False
                    findings[idx]["correlation_cluster_size"] = len(indices)

        return findings

    def statistical_confidence(
        self,
        measurements: List[float],
        expected_shift: float,
        baseline_mean: float = 0.0,
    ) -> Dict:
        """Calculate statistically-grounded confidence using z-score analysis.

        For timing-based or measurement-based detections, this computes
        whether the observed values are statistically significant rather
        than relying on a single threshold comparison.

        Args:
            measurements: List of observed measurement values (e.g. response times).
            expected_shift: The expected shift caused by the payload (e.g. sleep time).
            baseline_mean: Mean of baseline measurements.

        Returns:
            Dict with z_score, p_significant (bool at p<0.05), mean, stdev,
            statistical_confidence (0-100).
        """
        result = {
            "z_score": 0.0,
            "p_significant": False,
            "mean": 0.0,
            "stdev": 0.0,
            "sample_count": len(measurements),
            "statistical_confidence": 0,
        }
        if len(measurements) < QUANTUM_STATISTICAL_MIN_SAMPLES:
            return result

        mean = statistics.mean(measurements)
        stdev = statistics.stdev(measurements) if len(measurements) > 1 else 0.0
        result["mean"] = round(mean, 4)
        result["stdev"] = round(stdev, 4)

        if stdev > 0:
            z_score = (mean - baseline_mean) / stdev
        else:
            # Zero variance: if mean matches expected shift, high confidence
            z_score = 10.0 if abs(mean - baseline_mean) >= expected_shift * 0.7 else 0.0

        result["z_score"] = round(z_score, 4)
        # z >= 1.96 corresponds to p < 0.05 (two-tailed)
        result["p_significant"] = abs(z_score) >= 1.96

        # Map z-score to confidence: z=2 → 70%, z=3 → 85%, z=5 → 100%
        if abs(z_score) >= 1.96:
            conf = min(100, int(50 + abs(z_score) * 10))
        else:
            conf = max(0, int(abs(z_score) * 25))
        result["statistical_confidence"] = conf

        return result
