"""Multi-stage injection confirmation to eliminate false positives.
For authorized security testing only.

Implements the Probe → Confirm → Baseline verification pipeline:

1. **Probe**: Inject a unique marker (VS_<hash>_1) and check for reflection
   or behavioural change.
2. **Confirm**: Inject a *different* marker (VS_<hash>_2) at the same
   injection point.  If both markers independently trigger the same class
   of change, the finding is confirmed.
3. **Baseline**: Optionally send a benign value to verify that normal input
   does *not* cause the same change (rules out dynamic content FPs).
"""
import time
import logging
from typing import Callable, Dict, Optional, Tuple

import requests

from core.injection_context import ConfirmationMarker
from core.raw_response import RawResponseAnalyzer
from core.utils import make_request

logger = logging.getLogger("venomstrike.confirmation")


class InjectionConfirmer:
    """Two-marker confirmation for injection findings.

    Usage::

        confirmer = InjectionConfirmer(session)
        result = confirmer.confirm(
            inject_func=lambda marker: inject_and_get_response(marker),
            check_func=lambda resp, marker: marker in resp.text,
        )
        if result["confirmed"]:
            # High-confidence finding
    """

    def __init__(self, session: requests.Session):
        self.session = session

    def confirm(
        self,
        inject_func: Callable[[str], Optional[requests.Response]],
        check_func: Callable[[requests.Response, str], bool],
        baseline_func: Callable[[], Optional[requests.Response]] = None,
    ) -> Dict:
        """Run the probe → confirm → baseline pipeline.

        Args:
            inject_func: Callable that takes a marker string and returns
                the HTTP response after injecting it.
            check_func: Callable(response, marker) → bool that returns
                True if the response shows evidence of injection.
            baseline_func: Optional callable() → Response that sends a
                benign (non-payload) request for comparison.

        Returns:
            Dict with keys: confirmed (bool), probe_matched, confirm_matched,
            baseline_clean, markers, confidence_boost.
        """
        marker1, marker2 = ConfirmationMarker.pair()

        result: Dict = {
            "confirmed": False,
            "probe_matched": False,
            "confirm_matched": False,
            "baseline_clean": True,
            "markers": (marker1, marker2),
            "confidence_boost": 0,
        }

        # Stage 1: Probe with first marker
        try:
            resp1 = inject_func(marker1)
            if resp1 is not None and check_func(resp1, marker1):
                result["probe_matched"] = True
        except Exception as exc:
            logger.debug("Probe stage failed: %s", exc)
            return result

        if not result["probe_matched"]:
            return result

        # Stage 2: Confirm with second marker
        try:
            resp2 = inject_func(marker2)
            if resp2 is not None and check_func(resp2, marker2):
                result["confirm_matched"] = True
        except Exception as exc:
            logger.debug("Confirm stage failed: %s", exc)

        # Stage 3: Baseline check (optional)
        if baseline_func is not None:
            try:
                baseline_resp = baseline_func()
                if baseline_resp is not None:
                    # Baseline should NOT trigger the check
                    if check_func(baseline_resp, marker1) or check_func(baseline_resp, marker2):
                        result["baseline_clean"] = False
            except Exception as exc:
                logger.debug("Baseline check failed: %s", exc)

        # Determine confirmation result
        if result["probe_matched"] and result["confirm_matched"] and result["baseline_clean"]:
            result["confirmed"] = True
            result["confidence_boost"] = 15
        elif result["probe_matched"] and result["confirm_matched"]:
            # Both markers matched but baseline wasn't clean
            result["confidence_boost"] = 5
        elif result["probe_matched"]:
            result["confidence_boost"] = 0

        return result

    def confirm_timing(
        self,
        inject_func: Callable[[str], Tuple[Optional[requests.Response], float]],
        baseline_time: float,
        sleep_seconds: float = 5.0,
        tolerance: float = 1.5,
    ) -> Dict:
        """Confirm a timing-based injection with two independent attempts.

        Args:
            inject_func: Callable(payload) → (response, elapsed_seconds).
            baseline_time: Normal response time in seconds.
            sleep_seconds: Expected delay from the timing payload.
            tolerance: Allowed variance.

        Returns:
            Dict with confirmed, attempts, timings.
        """
        threshold = baseline_time + sleep_seconds - tolerance
        threshold = max(threshold, sleep_seconds * 0.7)

        timings = []
        confirmations = 0

        for attempt in range(2):
            try:
                _, elapsed = inject_func(f"timing_attempt_{attempt}")
                timings.append(elapsed)
                if elapsed >= threshold:
                    confirmations += 1
            except Exception as exc:
                logger.debug("Timing confirmation attempt %d failed: %s", attempt, exc)
                timings.append(0.0)
            time.sleep(0.5)

        return {
            "confirmed": confirmations >= 2,
            "attempts": 2,
            "confirmations": confirmations,
            "timings": timings,
            "threshold": threshold,
            "confidence_boost": 15 if confirmations >= 2 else 0,
        }
