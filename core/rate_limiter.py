"""Adaptive Rate Limiter — intelligent request throttling.

Chimera Edition (v9.0) introduces adaptive rate limiting that dynamically
adjusts request speed based on target response times, error rates, and
detected rate-limiting behaviour.  This prevents accidental denial-of-service
during authorized security testing while maximizing scan throughput.

Key capabilities:
- **Response-time tracking**: Monitors moving average of response latencies
  and slows down when the target shows signs of stress.
- **Error-rate detection**: Backs off exponentially when HTTP 429 / 503 /
  connection errors spike.
- **Recovery ramp-up**: Gradually increases speed once the target stabilises.
- **Per-host isolation**: Maintains separate state per target host so
  multi-host scans don't interfere with each other.

For authorized security testing only.
"""
import logging
import threading
import time
from collections import deque
from typing import Dict, Optional

from config import (
    ADAPTIVE_RATE_LIMITING,
    RATE_LIMIT_ERROR_THRESHOLD,
    RATE_LIMIT_MAX_DELAY,
    RATE_LIMIT_MIN_DELAY,
)

logger = logging.getLogger("venomstrike.rate_limiter")

# HTTP status codes that indicate rate limiting or server stress
RATE_LIMIT_STATUS_CODES = {429, 503, 502, 504}


class HostState:
    """Per-host rate-limiting state.

    Tracks recent response times and error counts to compute an
    appropriate inter-request delay for a specific host.
    """

    __slots__ = (
        "host", "_lock", "_response_times", "_error_count",
        "_consecutive_errors", "_current_delay", "_last_request_time",
        "_window_size",
    )

    def __init__(self, host: str, window_size: int = 50):
        self.host = host
        self._lock = threading.Lock()
        self._response_times: deque = deque(maxlen=window_size)
        self._error_count = 0
        self._consecutive_errors = 0
        self._current_delay = RATE_LIMIT_MIN_DELAY
        self._last_request_time = 0.0
        self._window_size = window_size

    @property
    def current_delay(self) -> float:
        return self._current_delay

    @property
    def avg_response_time(self) -> float:
        with self._lock:
            if not self._response_times:
                return 0.0
            return sum(self._response_times) / len(self._response_times)

    @property
    def error_count(self) -> int:
        return self._error_count

    def record_success(self, response_time: float, status_code: int = 200) -> None:
        """Record a successful request and adjust delay downward."""
        with self._lock:
            self._response_times.append(response_time)
            self._consecutive_errors = 0

            if status_code in RATE_LIMIT_STATUS_CODES:
                self._handle_rate_limit_response()
                return

            # Gradual recovery — reduce delay toward minimum
            if self._current_delay > RATE_LIMIT_MIN_DELAY:
                self._current_delay = max(
                    RATE_LIMIT_MIN_DELAY,
                    self._current_delay * 0.85,
                )

            # If response times are climbing, slow down proactively
            if len(self._response_times) >= 10:
                recent = list(self._response_times)[-5:]
                older = list(self._response_times)[-10:-5]
                recent_avg = sum(recent) / len(recent)
                older_avg = sum(older) / len(older)
                if older_avg > 0 and recent_avg > older_avg * 1.5:
                    self._current_delay = min(
                        RATE_LIMIT_MAX_DELAY,
                        self._current_delay * 1.3,
                    )
                    logger.debug(
                        "Rate limiter [%s]: response times increasing "
                        "(%.2fs → %.2fs), delay → %.2fs",
                        self.host, older_avg, recent_avg, self._current_delay,
                    )

    def record_error(self, is_rate_limit: bool = False) -> None:
        """Record a failed request and adjust delay upward."""
        with self._lock:
            self._error_count += 1
            self._consecutive_errors += 1

            if is_rate_limit or self._consecutive_errors >= RATE_LIMIT_ERROR_THRESHOLD:
                self._handle_rate_limit_response()
            else:
                # Mild increase for non-rate-limit errors
                self._current_delay = min(
                    RATE_LIMIT_MAX_DELAY,
                    self._current_delay * 1.2,
                )

    def _handle_rate_limit_response(self) -> None:
        """Exponential backoff for confirmed rate limiting."""
        backoff_factor = min(2.0 ** self._consecutive_errors, 16.0)
        self._current_delay = min(
            RATE_LIMIT_MAX_DELAY,
            max(self._current_delay, RATE_LIMIT_MIN_DELAY) * backoff_factor,
        )
        logger.info(
            "Rate limiter [%s]: rate limited (consecutive=%d), "
            "delay → %.2fs",
            self.host, self._consecutive_errors, self._current_delay,
        )

    def wait(self) -> float:
        """Wait the appropriate delay before the next request.

        Returns the actual time waited in seconds.
        """
        with self._lock:
            delay = self._current_delay
            now = time.monotonic()
            elapsed = now - self._last_request_time
            actual_wait = max(0.0, delay - elapsed)

        if actual_wait > 0:
            time.sleep(actual_wait)

        with self._lock:
            self._last_request_time = time.monotonic()

        return actual_wait

    def get_stats(self) -> Dict:
        """Return current rate-limiting statistics for this host."""
        return {
            "host": self.host,
            "current_delay": round(self._current_delay, 4),
            "avg_response_time": round(self.avg_response_time, 4),
            "error_count": self._error_count,
            "consecutive_errors": self._consecutive_errors,
            "samples": len(self._response_times),
        }


class AdaptiveRateLimiter:
    """Global rate limiter with per-host state tracking.

    Usage::

        limiter = AdaptiveRateLimiter()

        # Before each request
        limiter.wait("example.com")

        # After each request
        limiter.record_success("example.com", response_time=0.45, status_code=200)
        # or
        limiter.record_error("example.com", is_rate_limit=True)

        # Get stats
        stats = limiter.get_all_stats()
    """

    def __init__(self, enabled: bool = None):
        self._enabled = enabled if enabled is not None else ADAPTIVE_RATE_LIMITING
        self._hosts: Dict[str, HostState] = {}
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _get_host_state(self, host: str) -> HostState:
        """Get or create per-host state."""
        with self._lock:
            if host not in self._hosts:
                self._hosts[host] = HostState(host)
            return self._hosts[host]

    def wait(self, host: str) -> float:
        """Wait the appropriate delay for the given host.

        Returns the time waited (0.0 if rate limiting is disabled).
        """
        if not self._enabled:
            return 0.0
        state = self._get_host_state(host)
        return state.wait()

    def record_success(
        self, host: str, response_time: float, status_code: int = 200,
    ) -> None:
        """Record a successful response for delay adjustment."""
        if not self._enabled:
            return
        state = self._get_host_state(host)
        state.record_success(response_time, status_code)

    def record_error(self, host: str, is_rate_limit: bool = False) -> None:
        """Record an error for delay adjustment."""
        if not self._enabled:
            return
        state = self._get_host_state(host)
        state.record_error(is_rate_limit)

    def get_host_stats(self, host: str) -> Optional[Dict]:
        """Get stats for a specific host."""
        with self._lock:
            state = self._hosts.get(host)
        if state is None:
            return None
        return state.get_stats()

    def get_all_stats(self) -> Dict[str, Dict]:
        """Get stats for all tracked hosts."""
        with self._lock:
            hosts = dict(self._hosts)
        return {host: state.get_stats() for host, state in hosts.items()}

    def reset(self, host: str = None) -> None:
        """Reset state for a host or all hosts."""
        with self._lock:
            if host:
                self._hosts.pop(host, None)
            else:
                self._hosts.clear()
