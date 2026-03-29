"""Adaptive Scan Profiler — dynamic target behaviour profiling.

Phoenix Edition (v10.0) introduces an adaptive scan profiler that
monitors target behaviour during scanning and dynamically adjusts
the scanning strategy for optimal performance.

Key capabilities:
- **Response-time profiling**: Builds a statistical model of the
  target's response times to detect anomalies and set optimal
  timing thresholds.
- **Error-rate monitoring**: Tracks error rates and adapts scanning
  intensity to stay below detection thresholds.
- **Endpoint clustering**: Groups endpoints by response behaviour
  to focus deep scanning on the most promising clusters.
- **Dynamic depth adjustment**: Increases scan depth for endpoints
  that show signs of vulnerabilities and decreases for hardened ones.
- **Resource-aware scheduling**: Throttles scanning when the target
  shows signs of stress (high latency, errors).

For authorized security testing only.
"""
import logging
import statistics
import time
from typing import Dict, List, Optional, Tuple

from config import (
    SCAN_PROFILER_ENABLED,
    SCAN_PROFILER_WINDOW_SIZE,
    SCAN_PROFILER_ERROR_THRESHOLD,
    SCAN_PROFILER_LATENCY_MULTIPLIER,
)

logger = logging.getLogger("venomstrike.scan_profiler")


class EndpointProfile:
    """Statistical profile for an individual endpoint."""

    __slots__ = (
        "url", "response_times", "status_codes", "error_count",
        "success_count", "has_findings", "depth_boost",
    )

    def __init__(self, url: str):
        self.url = url
        self.response_times: List[float] = []
        self.status_codes: List[int] = []
        self.error_count = 0
        self.success_count = 0
        self.has_findings = False
        self.depth_boost = 0

    def record(self, response_time: float, status_code: int) -> None:
        """Record a response observation."""
        self.response_times.append(response_time)
        self.status_codes.append(status_code)
        if status_code >= 500 or status_code in (429, 403):
            self.error_count += 1
        else:
            self.success_count += 1

    @property
    def avg_response_time(self) -> float:
        """Average response time, or 0.0 if no observations."""
        return statistics.mean(self.response_times) if self.response_times else 0.0

    @property
    def p95_response_time(self) -> float:
        """95th percentile response time."""
        if len(self.response_times) < 2:
            return self.avg_response_time
        sorted_times = sorted(self.response_times)
        idx = int(len(sorted_times) * 0.95)
        return sorted_times[min(idx, len(sorted_times) - 1)]

    @property
    def error_rate(self) -> float:
        """Error rate as a fraction (0.0–1.0)."""
        total = self.error_count + self.success_count
        return self.error_count / total if total > 0 else 0.0

    def to_dict(self) -> Dict:
        """Serialise profile to a dictionary."""
        return {
            "url": self.url,
            "avg_response_time": round(self.avg_response_time, 3),
            "p95_response_time": round(self.p95_response_time, 3),
            "error_rate": round(self.error_rate, 3),
            "observations": len(self.response_times),
            "has_findings": self.has_findings,
            "depth_boost": self.depth_boost,
        }


class ScanProfiler:
    """Dynamically profiles target behaviour and adapts scan strategy.

    Usage:
        profiler = ScanProfiler()
        profiler.record_response("/api/users", 0.15, 200)
        profiler.record_response("/api/admin", 0.85, 403)
        recommendation = profiler.get_recommendation("/api/users")
    """

    def __init__(
        self,
        window_size: int = None,
        error_threshold: float = None,
        latency_multiplier: float = None,
    ):
        self.window_size = (
            window_size if window_size is not None else SCAN_PROFILER_WINDOW_SIZE
        )
        self.error_threshold = (
            error_threshold
            if error_threshold is not None
            else SCAN_PROFILER_ERROR_THRESHOLD
        )
        self.latency_multiplier = (
            latency_multiplier
            if latency_multiplier is not None
            else SCAN_PROFILER_LATENCY_MULTIPLIER
        )
        self._profiles: Dict[str, EndpointProfile] = {}
        self._global_times: List[float] = []
        self._global_errors = 0
        self._global_total = 0
        self._target_stressed = False

    # ── Public API ──────────────────────────────────────────────

    def record_response(
        self, url: str, response_time: float, status_code: int,
    ) -> None:
        """Record an observation for an endpoint."""
        if not SCAN_PROFILER_ENABLED:
            return

        profile = self._profiles.setdefault(url, EndpointProfile(url))
        profile.record(response_time, status_code)

        # Global tracking (sliding window)
        self._global_times.append(response_time)
        if len(self._global_times) > self.window_size:
            self._global_times = self._global_times[-self.window_size:]

        self._global_total += 1
        if status_code >= 500 or status_code in (429, 403):
            self._global_errors += 1

        # Check for target stress
        self._update_stress_status()

    def record_finding(self, url: str) -> None:
        """Mark an endpoint as having yielded findings."""
        if not SCAN_PROFILER_ENABLED:
            return
        profile = self._profiles.setdefault(url, EndpointProfile(url))
        profile.has_findings = True
        profile.depth_boost = min(profile.depth_boost + 1, 5)

    def get_recommendation(self, url: str) -> Dict:
        """Get scanning recommendation for an endpoint.

        Returns a dict with:
        - ``should_scan``: Whether to continue scanning this endpoint.
        - ``depth_modifier``: Suggested depth adjustment (-2 to +3).
        - ``delay_suggestion``: Suggested inter-request delay.
        - ``reason``: Human-readable explanation.
        """
        if not SCAN_PROFILER_ENABLED:
            return {
                "should_scan": True,
                "depth_modifier": 0,
                "delay_suggestion": 0.0,
                "reason": "Profiling disabled",
            }

        profile = self._profiles.get(url)

        # No data yet — proceed with defaults
        if profile is None or not profile.response_times:
            return {
                "should_scan": True,
                "depth_modifier": 0,
                "delay_suggestion": 0.0,
                "reason": "No observations yet",
            }

        # High error rate → skip or reduce depth
        if profile.error_rate > self.error_threshold:
            return {
                "should_scan": profile.error_rate < 0.9,
                "depth_modifier": -2,
                "delay_suggestion": 2.0,
                "reason": f"High error rate ({profile.error_rate:.0%})",
            }

        # Target under stress → slow down globally
        if self._target_stressed:
            return {
                "should_scan": True,
                "depth_modifier": -1,
                "delay_suggestion": 1.5,
                "reason": "Target showing signs of stress",
            }

        # Endpoint has findings → increase depth
        if profile.has_findings:
            return {
                "should_scan": True,
                "depth_modifier": min(profile.depth_boost, 3),
                "delay_suggestion": 0.0,
                "reason": f"Findings detected (boost +{profile.depth_boost})",
            }

        # Normal endpoint — check if response time is anomalously high
        global_avg = self._global_avg_time()
        if global_avg > 0 and profile.avg_response_time > global_avg * self.latency_multiplier:
            return {
                "should_scan": True,
                "depth_modifier": -1,
                "delay_suggestion": 0.5,
                "reason": "High latency endpoint",
            }

        return {
            "should_scan": True,
            "depth_modifier": 0,
            "delay_suggestion": 0.0,
            "reason": "Normal endpoint behaviour",
        }

    def get_prioritised_endpoints(self) -> List[Dict]:
        """Return endpoints sorted by scanning priority.

        Endpoints with findings are prioritised, followed by low-error
        endpoints, then high-error endpoints.
        """
        profiles = list(self._profiles.values())

        def score(p: EndpointProfile) -> Tuple[int, float]:
            finding_priority = 0 if p.has_findings else 1
            return (finding_priority, p.error_rate)

        profiles.sort(key=score)
        return [p.to_dict() for p in profiles]

    def is_target_stressed(self) -> bool:
        """Check if the target appears to be under stress."""
        return self._target_stressed

    def get_global_stats(self) -> Dict:
        """Return global scanning statistics."""
        global_avg = self._global_avg_time()
        global_error_rate = (
            self._global_errors / self._global_total
            if self._global_total > 0
            else 0.0
        )
        return {
            "total_requests": self._global_total,
            "avg_response_time": round(global_avg, 3),
            "global_error_rate": round(global_error_rate, 3),
            "target_stressed": self._target_stressed,
            "endpoints_profiled": len(self._profiles),
        }

    # ── Internal helpers ────────────────────────────────────────

    def _global_avg_time(self) -> float:
        """Compute global average response time."""
        return statistics.mean(self._global_times) if self._global_times else 0.0

    def _update_stress_status(self) -> None:
        """Update whether the target appears stressed."""
        if self._global_total < 10:
            return
        recent_errors = sum(
            1 for t in self._global_times[-20:]
            if t > (self._global_avg_time() * self.latency_multiplier)
        )
        error_rate = (
            self._global_errors / self._global_total
            if self._global_total > 0
            else 0.0
        )
        self._target_stressed = (
            error_rate > self.error_threshold or recent_errors > 5
        )
