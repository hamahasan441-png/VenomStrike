"""Injection context analysis and marker generation for multi-stage confirmation.
For authorized security testing only.
"""
import uuid
import hashlib
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class InjectionPoint:
    """Describes a single injection point with context metadata."""
    url: str = ""
    param: str = ""
    method: str = "GET"
    param_type: str = "query"      # query, body, header, cookie, path, json
    data_type: str = "string"      # string, integer, json, xml, url
    context: str = "unknown"       # reflected, stored, blind, header
    technology: str = ""           # detected tech (mysql, php, etc.)


class ConfirmationMarker:
    """Generate unique, unlikely-to-collide markers for injection confirmation."""

    PREFIX = "VS"

    @staticmethod
    def generate(stage: int = 1) -> str:
        """Return a unique marker like VS_a1b2c3d4_1."""
        tag = uuid.uuid4().hex[:8]
        return f"{ConfirmationMarker.PREFIX}_{tag}_{stage}"

    @staticmethod
    def pair() -> Tuple[str, str]:
        """Return a probe marker and a confirmation marker."""
        tag = uuid.uuid4().hex[:8]
        return f"{ConfirmationMarker.PREFIX}_{tag}_1", f"{ConfirmationMarker.PREFIX}_{tag}_2"

    @staticmethod
    def is_marker(text: str) -> bool:
        """Check if text contains any VS confirmation marker."""
        return bool(re.search(r"VS_[a-f0-9]{8}_\d", text))


class InjectionContextAnalyzer:
    """Classify injection points by context and recommend testing strategy."""

    # Parameters that likely accept URLs
    URL_PARAMS = {"url", "uri", "link", "src", "href", "dest", "redirect",
                  "next", "target", "path", "endpoint", "callback", "fetch",
                  "load", "file", "return", "goto", "continue"}

    # Parameters that likely accept numeric IDs
    ID_PARAMS = {"id", "uid", "pid", "page", "num", "count", "limit",
                 "offset", "index", "order", "sort"}

    # Parameters that likely accept search / text
    TEXT_PARAMS = {"q", "query", "search", "name", "title", "comment",
                   "message", "text", "body", "content", "value", "input"}

    def classify_param(self, param: str, value: str = "") -> Dict:
        """Classify a parameter's likely data type and injection context.

        Returns a dict with keys: data_type, param_type, ssrf_candidate,
        sqli_candidate, xss_candidate.
        """
        p = param.lower().strip()
        result = {
            "data_type": "string",
            "param_type": "query",
            "ssrf_candidate": p in self.URL_PARAMS,
            "sqli_candidate": p in self.ID_PARAMS or p in self.TEXT_PARAMS,
            "xss_candidate": p in self.TEXT_PARAMS,
        }

        # Infer data type from name or value
        if p in self.ID_PARAMS or (value and value.isdigit()):
            result["data_type"] = "integer"
        elif p in self.URL_PARAMS or (value and value.startswith(("http://", "https://"))):
            result["data_type"] = "url"

        return result

    def detect_reflection(self, response_text: str, marker: str) -> str:
        """Check if a marker is reflected in the response.

        Returns 'reflected', 'encoded', or 'absent'.
        """
        if marker in response_text:
            return "reflected"
        # Check common HTML-entity encodings
        encoded = marker.replace("<", "&lt;").replace(">", "&gt;")
        if encoded != marker and encoded in response_text:
            return "encoded"
        return "absent"

    def detect_response_context(self, response_text: str, marker: str) -> str:
        """Determine the HTML context where the marker appears.

        Returns: 'tag_content', 'attribute', 'script', 'comment', 'style', 'none'.
        """
        if marker not in response_text:
            return "none"

        idx = response_text.find(marker)
        before = response_text[max(0, idx - 200):idx]

        # Inside a script block?
        if "<script" in before.lower() and "</script>" not in before.lower():
            return "script"
        # Inside an HTML comment?
        if "<!--" in before and "-->" not in before:
            return "comment"
        # Inside a style block?
        if "<style" in before.lower() and "</style>" not in before.lower():
            return "style"
        # Inside an attribute value? (look for last unmatched quote)
        last_quote = max(before.rfind('"'), before.rfind("'"))
        last_tag_open = before.rfind("<")
        last_tag_close = before.rfind(">")
        if last_quote > last_tag_close and last_tag_open > last_tag_close:
            return "attribute"

        return "tag_content"

    def recommend_payloads(self, context: str, data_type: str,
                           technology: str = "") -> List[str]:
        """Suggest payload strategies based on context analysis.

        Returns a list of strategy identifiers (not actual payloads).
        """
        strategies = []
        tech_lower = technology.lower()

        if data_type == "integer":
            strategies.append("numeric_sqli")
        if data_type == "url":
            strategies.append("ssrf")
            strategies.append("open_redirect")

        if context == "tag_content":
            strategies.append("xss_tag_injection")
        elif context == "attribute":
            strategies.append("xss_attribute_breakout")
        elif context == "script":
            strategies.append("xss_js_injection")

        if "mysql" in tech_lower:
            strategies.append("mysql_sqli")
        elif "postgres" in tech_lower:
            strategies.append("postgres_sqli")
        elif "mssql" in tech_lower or "sql server" in tech_lower:
            strategies.append("mssql_sqli")

        if not strategies:
            strategies.append("generic")
        return strategies
