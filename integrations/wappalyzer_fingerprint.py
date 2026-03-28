"""Wappalyzer-style technology fingerprinting integration.
For authorized security testing only.
"""
import json
import logging
import re
from typing import Dict, List, Optional

import requests

from config import WAPPALYZER_ENABLED

logger = logging.getLogger("venomstrike.integrations.wappalyzer")


class WappalyzerFingerprint:
    """Detect web technologies by analysing HTTP headers, HTML content,
    and JavaScript signatures.

    This is a lightweight, self-contained fingerprinter inspired by the
    Wappalyzer methodology.  It does **not** require the Wappalyzer CLI
    or API — it ships with built-in signatures for the most common
    technologies.

    For authorized security testing only.
    """

    # ------------------------------------------------------------------
    # Built-in technology signatures
    # ------------------------------------------------------------------
    # Each entry: (name, category, detection_rules)
    # detection_rules is a dict with optional keys:
    #   "headers" : {header_name: regex_pattern}
    #   "html"    : [regex_pattern, ...]
    #   "meta"    : {meta_name: regex_pattern}
    #   "scripts" : [regex_pattern, ...]
    #   "cookies" : {cookie_name: regex_pattern}

    SIGNATURES: List[Dict] = [
        {
            "name": "Nginx",
            "category": "Web Server",
            "headers": {"Server": r"nginx"},
        },
        {
            "name": "Apache",
            "category": "Web Server",
            "headers": {"Server": r"Apache"},
        },
        {
            "name": "IIS",
            "category": "Web Server",
            "headers": {"Server": r"Microsoft-IIS"},
        },
        {
            "name": "Cloudflare",
            "category": "CDN/WAF",
            "headers": {"Server": r"cloudflare", "CF-RAY": r".+"},
        },
        {
            "name": "PHP",
            "category": "Language",
            "headers": {"X-Powered-By": r"PHP"},
            "cookies": {"PHPSESSID": r".+"},
        },
        {
            "name": "ASP.NET",
            "category": "Framework",
            "headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r".+"},
            "cookies": {"ASP.NET_SessionId": r".+"},
        },
        {
            "name": "Django",
            "category": "Framework",
            "cookies": {"csrftoken": r".+"},
            "html": [r"csrfmiddlewaretoken"],
        },
        {
            "name": "Flask",
            "category": "Framework",
            "headers": {"Server": r"Werkzeug"},
        },
        {
            "name": "Express",
            "category": "Framework",
            "headers": {"X-Powered-By": r"Express"},
        },
        {
            "name": "WordPress",
            "category": "CMS",
            "html": [r"wp-content", r"wp-includes", r"wp-json"],
            "meta": {"generator": r"WordPress"},
        },
        {
            "name": "Drupal",
            "category": "CMS",
            "headers": {"X-Generator": r"Drupal"},
            "html": [r"Drupal\.settings", r"sites/default/files"],
        },
        {
            "name": "Joomla",
            "category": "CMS",
            "html": [r"/media/jui/", r"Joomla!"],
            "meta": {"generator": r"Joomla"},
        },
        {
            "name": "React",
            "category": "JS Framework",
            "html": [r"__NEXT_DATA__", r"data-reactroot", r"_react"],
            "scripts": [r"react\.production\.min\.js", r"react-dom"],
        },
        {
            "name": "Vue.js",
            "category": "JS Framework",
            "html": [r"data-v-[a-f0-9]", r"__vue__"],
            "scripts": [r"vue\.min\.js", r"vue\.runtime"],
        },
        {
            "name": "Angular",
            "category": "JS Framework",
            "html": [r"ng-version", r"ng-app"],
            "scripts": [r"angular\.min\.js", r"zone\.js"],
        },
        {
            "name": "jQuery",
            "category": "JS Library",
            "scripts": [r"jquery[\.-][\d\.]+\.min\.js", r"jquery\.min\.js"],
        },
        {
            "name": "Bootstrap",
            "category": "CSS Framework",
            "html": [r"bootstrap\.min\.css", r"bootstrap\.min\.js"],
        },
        {
            "name": "Tailwind CSS",
            "category": "CSS Framework",
            "html": [r"tailwindcss", r"tailwind\.min\.css"],
        },
        {
            "name": "Google Analytics",
            "category": "Analytics",
            "html": [r"google-analytics\.com/analytics\.js", r"gtag/js"],
            "scripts": [r"googletagmanager\.com"],
        },
        {
            "name": "reCAPTCHA",
            "category": "Security",
            "html": [r"recaptcha", r"g-recaptcha"],
            "scripts": [r"recaptcha/api\.js"],
        },
        {
            "name": "Varnish",
            "category": "Cache",
            "headers": {"Via": r"varnish", "X-Varnish": r".+"},
        },
        {
            "name": "Redis",
            "category": "Cache",
            "cookies": {"_redis_session": r".+"},
        },
        {
            "name": "Amazon S3",
            "category": "Cloud Storage",
            "headers": {"x-amz-request-id": r".+", "Server": r"AmazonS3"},
        },
        {
            "name": "GraphQL",
            "category": "API",
            "html": [r"graphql", r"__schema"],
        },
    ]

    def __init__(self):
        self._enabled = WAPPALYZER_ENABLED

    def is_available(self) -> bool:
        """Return *True* if fingerprinting is enabled in config."""
        return self._enabled

    # ------------------------------------------------------------------
    # Main fingerprinting entry point
    # ------------------------------------------------------------------

    def fingerprint(
        self,
        url: str,
        *,
        session: Optional[requests.Session] = None,
        timeout: int = 15,
    ) -> List[Dict]:
        """Fingerprint technologies on the target URL.

        Args:
            url: Target URL to fingerprint.
            session: Optional ``requests.Session`` (for cookie/proxy reuse).
            timeout: HTTP request timeout in seconds.

        Returns:
            A list of dicts with keys ``name``, ``category``, ``confidence``,
            ``evidence``.
        """
        if not self._enabled:
            logger.info("Wappalyzer fingerprinting is disabled")
            return []

        try:
            sess = session or requests.Session()
            resp = sess.get(url, timeout=timeout, verify=False, allow_redirects=True)
        except Exception as exc:
            logger.error("Fingerprint request failed: %s", exc)
            return []

        return self._analyse_response(resp)

    def fingerprint_from_response(self, response: requests.Response) -> List[Dict]:
        """Fingerprint technologies from an existing response object."""
        return self._analyse_response(response)

    # ------------------------------------------------------------------
    # Internal analysis
    # ------------------------------------------------------------------

    def _analyse_response(self, resp: requests.Response) -> List[Dict]:
        """Match response data against all signatures."""
        detections: List[Dict] = []
        body = resp.text[:50000]  # Limit body inspection size
        headers = {k: v for k, v in resp.headers.items()}
        cookies = {c.name: c.value for c in resp.cookies}

        for sig in self.SIGNATURES:
            matches = 0
            total_rules = 0
            evidence: List[str] = []

            # Header matching
            for hdr_name, pattern in sig.get("headers", {}).items():
                total_rules += 1
                hdr_val = headers.get(hdr_name, "")
                if re.search(pattern, hdr_val, re.IGNORECASE):
                    matches += 1
                    evidence.append(f"Header {hdr_name}: {hdr_val[:80]}")

            # HTML body patterns
            for pattern in sig.get("html", []):
                total_rules += 1
                if re.search(pattern, body, re.IGNORECASE):
                    matches += 1
                    evidence.append(f"HTML pattern: {pattern}")

            # Meta tag patterns
            for meta_name, pattern in sig.get("meta", {}).items():
                total_rules += 1
                meta_re = rf'<meta[^>]+name=["\']?{re.escape(meta_name)}["\']?[^>]+content=["\']([^"\']+)'
                m = re.search(meta_re, body, re.IGNORECASE)
                if m and re.search(pattern, m.group(1), re.IGNORECASE):
                    matches += 1
                    evidence.append(f"Meta {meta_name}: {m.group(1)[:80]}")

            # Script patterns
            for pattern in sig.get("scripts", []):
                total_rules += 1
                if re.search(pattern, body, re.IGNORECASE):
                    matches += 1
                    evidence.append(f"Script: {pattern}")

            # Cookie patterns
            for cookie_name, pattern in sig.get("cookies", {}).items():
                total_rules += 1
                cookie_val = cookies.get(cookie_name, "")
                if cookie_val and re.search(pattern, cookie_val, re.IGNORECASE):
                    matches += 1
                    evidence.append(f"Cookie: {cookie_name}")

            if matches > 0 and total_rules > 0:
                confidence = int((matches / total_rules) * 100)
                detections.append({
                    "name": sig["name"],
                    "category": sig["category"],
                    "confidence": confidence,
                    "evidence": evidence,
                })

        # Sort by confidence descending
        detections.sort(key=lambda d: d["confidence"], reverse=True)
        return detections
