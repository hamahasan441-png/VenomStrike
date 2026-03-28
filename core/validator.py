"""Result validator — multi-strategy re-testing with timing calibration."""
# For authorized security testing only.
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
from config import VALIDATION_ATTEMPTS, MIN_CONFIDENCE, TIMING_TOLERANCE

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

        Uses 5 samples (up from 3) and trims outliers for a more stable
        baseline, reducing false positives on variable-latency networks.

        Returns the median response time in seconds.
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
