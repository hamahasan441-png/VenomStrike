"""WAF detection and evasion — polymorphic payload encoding for injection testing.
For authorized security testing only.
"""
import re
import random
import urllib.parse
import time
import logging
from typing import Optional, List, Dict
import requests

logger = logging.getLogger("venomstrike.waf_evasion")


class WAFDetector:
    """Detect and identify Web Application Firewalls."""

    # Response patterns indicating a WAF block
    BLOCK_PATTERNS = [
        (r"access denied", "Generic WAF"),
        (r"403 forbidden", "Generic WAF/Server"),
        (r"request blocked", "Generic WAF"),
        (r"web application firewall", "Generic WAF"),
        (r"mod_security", "ModSecurity"),
        (r"noyb", "ModSecurity"),
        (r"cloudflare", "Cloudflare"),
        (r"cf-ray", "Cloudflare"),
        (r"attention required.*cloudflare", "Cloudflare"),
        (r"incapsula", "Imperva/Incapsula"),
        (r"x-sucuri", "Sucuri"),
        (r"blocked by.*waf", "Generic WAF"),
        (r"not acceptable.*406", "WAF 406 Block"),
    ]

    # Status codes that often indicate WAF blocking
    BLOCK_STATUS_CODES = {403, 406, 429, 503}

    def is_blocked(self, response: requests.Response) -> bool:
        """Check if a response indicates a WAF block."""
        if response is None:
            return False
        if response.status_code in self.BLOCK_STATUS_CODES:
            combined = f"{response.text[:2000]} {str(response.headers)}".lower()
            for pattern, _ in self.BLOCK_PATTERNS:
                if re.search(pattern, combined, re.IGNORECASE):
                    return True
        return False

    def identify_waf(self, response: requests.Response) -> str:
        """Identify which WAF is blocking the request."""
        if response is None:
            return "Unknown"
        combined = f"{response.text[:2000]} {str(response.headers)}".lower()
        for pattern, waf_name in self.BLOCK_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                return waf_name
        if response.status_code in self.BLOCK_STATUS_CODES:
            return "Unknown WAF (status code)"
        return "None"


class PayloadTransformer:
    """Transform payloads to evade WAF signatures while preserving semantics."""

    def transform(self, payload: str, techniques: List[str] = None) -> List[str]:
        """Generate multiple evasion variants of a payload.

        Args:
            payload: Original payload string.
            techniques: List of technique names to apply. If None, apply all.

        Returns:
            List of transformed payloads (always includes original).
        """
        if techniques is None:
            techniques = ["case_variation", "comment_injection",
                         "url_encode", "double_url_encode",
                         "whitespace_variation"]

        variants = [payload]  # Always include original

        for technique in techniques:
            method = getattr(self, f"_apply_{technique}", None)
            if method:
                result = method(payload)
                if result and result != payload and result not in variants:
                    variants.append(result)

        return variants

    def _apply_case_variation(self, payload: str) -> str:
        """Randomize case of SQL/HTML keywords."""
        keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR",
                    "INSERT", "UPDATE", "DELETE", "DROP", "SLEEP",
                    "WAITFOR", "DELAY", "BENCHMARK",
                    "script", "alert", "onerror", "onload", "img", "svg"]
        result = payload
        for kw in keywords:
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            def randomize_case(m):
                return "".join(
                    c.upper() if random.random() > 0.5 else c.lower()
                    for c in m.group()
                )
            result = pattern.sub(randomize_case, result)
        return result

    def _apply_comment_injection(self, payload: str) -> str:
        """Insert SQL comments between keywords to break WAF signatures."""
        # Insert /**/ between SQL keywords
        sql_kw = re.compile(
            r"\b(SELECT|UNION|FROM|WHERE|AND|OR|INSERT|UPDATE|DELETE|SLEEP)\b",
            re.IGNORECASE,
        )
        return sql_kw.sub(lambda m: f"/**/{m.group()}/**/", payload)

    def _apply_url_encode(self, payload: str) -> str:
        """URL-encode special characters."""
        return urllib.parse.quote(payload, safe="")

    def _apply_double_url_encode(self, payload: str) -> str:
        """Double URL-encode the payload."""
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")

    def _apply_whitespace_variation(self, payload: str) -> str:
        """Replace spaces with alternative whitespace."""
        alternatives = ["%09", "%0a", "%0d", "+", "%20"]
        ws = random.choice(alternatives)
        return payload.replace(" ", ws)


class AdaptiveThrottle:
    """Adaptive rate limiting to avoid WAF blocks."""

    def __init__(self, base_delay: float = 0.5):
        self.base_delay = base_delay
        self.current_delay = base_delay
        self.consecutive_blocks = 0
        self.max_delay = 30.0

    def on_success(self):
        """Response was successful — decrease delay gradually."""
        self.consecutive_blocks = 0
        self.current_delay = max(self.base_delay, self.current_delay * 0.8)

    def on_block(self):
        """Response was blocked — increase delay with backoff."""
        self.consecutive_blocks += 1
        self.current_delay = min(
            self.max_delay,
            self.current_delay * (1.5 + self.consecutive_blocks * 0.5)
        )
        logger.debug("WAF block detected, delay increased to %.1fs", self.current_delay)

    def wait(self):
        """Sleep for the current adaptive delay."""
        jitter = random.uniform(0, self.current_delay * 0.2)
        time.sleep(self.current_delay + jitter)

    def get_delay(self) -> float:
        """Return current delay value."""
        return self.current_delay
