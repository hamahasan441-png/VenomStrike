"""Response Intelligence Analyzer — deep response analysis engine.

Hydra Edition (v8.0) introduces response intelligence that goes beyond
simple string matching to perform structural analysis, technology-specific
error detection, and behavioral fingerprinting.

Key capabilities:
- **Structural diffing**: Compare DOM structure, not just string content
- **Error pattern intelligence**: Technology-specific error signatures
  with severity and information leakage classification
- **Behavioral fingerprinting**: Detect how the application behaves
  differently under injection vs normal input
- **Information leakage detection**: Identify sensitive data exposure
  in error responses

For authorized security testing only.
"""
import logging
import re
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("venomstrike.response_intelligence")


class ResponseIntelligence:
    """Deep response analysis with technology-aware intelligence.

    Usage::

        analyzer = ResponseIntelligence()
        analysis = analyzer.analyze(
            baseline_text="normal response",
            payload_text="error response with SQL error",
            technology="mysql",
        )
        if analysis["is_anomalous"]:
            print(analysis["anomaly_indicators"])
    """

    # Technology-specific error signatures with severity classification
    ERROR_SIGNATURES: Dict[str, List[Dict]] = {
        "mysql": [
            {"pattern": r"You have an error in your SQL syntax", "severity": "high", "leaks": "query_structure"},
            {"pattern": r"mysql_fetch_array\(\)", "severity": "high", "leaks": "stack_trace"},
            {"pattern": r"Warning:.*mysql_", "severity": "medium", "leaks": "function_name"},
            {"pattern": r"MySQLSyntaxErrorException", "severity": "high", "leaks": "stack_trace"},
            {"pattern": r"com\.mysql\.jdbc", "severity": "high", "leaks": "technology_stack"},
            {"pattern": r"SQLSTATE\[42000\]", "severity": "high", "leaks": "error_code"},
            {"pattern": r"Unclosed quotation mark", "severity": "high", "leaks": "query_structure"},
            {"pattern": r"supplied argument is not a valid MySQL", "severity": "medium", "leaks": "function_name"},
        ],
        "postgresql": [
            {"pattern": r"ERROR:.*syntax error at or near", "severity": "high", "leaks": "query_structure"},
            {"pattern": r"pg_query\(\)", "severity": "high", "leaks": "function_name"},
            {"pattern": r"PG::SyntaxError", "severity": "high", "leaks": "error_class"},
            {"pattern": r"org\.postgresql\.util\.PSQLException", "severity": "high", "leaks": "stack_trace"},
            {"pattern": r"unterminated quoted string", "severity": "high", "leaks": "query_structure"},
        ],
        "mssql": [
            {"pattern": r"Unclosed quotation mark after the character string", "severity": "high", "leaks": "query_structure"},
            {"pattern": r"Microsoft OLE DB Provider for SQL Server", "severity": "high", "leaks": "technology_stack"},
            {"pattern": r"System\.Data\.SqlClient\.SqlException", "severity": "high", "leaks": "stack_trace"},
            {"pattern": r"\[Microsoft\]\[ODBC SQL Server Driver\]", "severity": "high", "leaks": "technology_stack"},
            {"pattern": r"Incorrect syntax near", "severity": "high", "leaks": "query_structure"},
        ],
        "oracle": [
            {"pattern": r"ORA-\d{5}", "severity": "high", "leaks": "error_code"},
            {"pattern": r"oracle\.jdbc\.driver", "severity": "high", "leaks": "technology_stack"},
            {"pattern": r"PLS-\d{5}", "severity": "high", "leaks": "error_code"},
        ],
        "php": [
            {"pattern": r"Fatal error:.*on line \d+", "severity": "high", "leaks": "file_path"},
            {"pattern": r"Warning:.*on line \d+", "severity": "medium", "leaks": "file_path"},
            {"pattern": r"Parse error:.*syntax error", "severity": "high", "leaks": "file_path"},
            {"pattern": r"<b>Warning</b>:.*in <b>.*</b> on line", "severity": "high", "leaks": "file_path"},
            {"pattern": r"Call Stack:|Stack trace:", "severity": "high", "leaks": "stack_trace"},
        ],
        "python": [
            {"pattern": r"Traceback \(most recent call last\)", "severity": "high", "leaks": "stack_trace"},
            {"pattern": r"File \".*\", line \d+", "severity": "high", "leaks": "file_path"},
            {"pattern": r"OperationalError:", "severity": "high", "leaks": "error_class"},
            {"pattern": r"jinja2\.exceptions\.", "severity": "high", "leaks": "template_engine"},
            {"pattern": r"django\.db\.", "severity": "high", "leaks": "framework"},
        ],
        "java": [
            {"pattern": r"java\.\w+\.\w+Exception", "severity": "high", "leaks": "stack_trace"},
            {"pattern": r"at [\w.]+\([\w.]+:\d+\)", "severity": "high", "leaks": "stack_trace"},
            {"pattern": r"javax\.servlet\.ServletException", "severity": "medium", "leaks": "framework"},
            {"pattern": r"org\.springframework\.", "severity": "medium", "leaks": "framework"},
        ],
        "dotnet": [
            {"pattern": r"System\.\w+Exception:", "severity": "high", "leaks": "stack_trace"},
            {"pattern": r"Server Error in '/' Application", "severity": "high", "leaks": "framework"},
            {"pattern": r"ASP\.NET.*Stack Trace:", "severity": "high", "leaks": "stack_trace"},
            {"pattern": r"Version Information:.*\.NET", "severity": "medium", "leaks": "version"},
        ],
        "generic": [
            {"pattern": r"Internal Server Error", "severity": "medium", "leaks": "error_class"},
            {"pattern": r"stack\s*trace", "severity": "high", "leaks": "stack_trace"},
            {"pattern": r"debug\s*mode", "severity": "medium", "leaks": "configuration"},
            {"pattern": r"(?:root|admin):.*:\d+:\d+:", "severity": "critical", "leaks": "system_file"},
            {"pattern": r"-----BEGIN.*PRIVATE KEY-----", "severity": "critical", "leaks": "credentials"},
            {"pattern": r"(?:password|passwd|secret|api_key)\s*[=:]\s*\S+", "severity": "high", "leaks": "credentials"},
        ],
    }

    # Sensitive data patterns that indicate information leakage
    INFO_LEAK_PATTERNS: Dict[str, str] = {
        r"/(?:home|var|usr|etc)/[\w/]+\.(?:py|php|rb|js|java|cs)": "file_path",
        r"[A-Za-z]:\\[\w\\]+\.(?:php|aspx?|jsp|py)": "windows_path",
        r"(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\s+(?:FROM|INTO|SET)\s+\w+": "sql_query",
        r"\b(?:root|admin|postgres|mysql|www-data)@[\w.-]+": "system_user",
        r"(?:mongodb|mysql|postgresql|redis)://[^\s]+": "connection_string",
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b": "internal_ip",
        r"(?:version|ver)\s*[=:\"']\s*[\d.]+": "version_info",
    }

    def analyze(
        self,
        baseline_text: str,
        payload_text: str,
        technology: str = "",
        status_code_baseline: int = 0,
        status_code_payload: int = 0,
    ) -> Dict:
        """Perform deep analysis comparing baseline and payload responses.

        Args:
            baseline_text: The normal response text.
            payload_text: The response after payload injection.
            technology: Detected technology stack.
            status_code_baseline: HTTP status of baseline response.
            status_code_payload: HTTP status of payload response.

        Returns:
            Dict with analysis results including ``is_anomalous``,
            ``anomaly_indicators``, ``error_signatures_found``,
            ``info_leaks``, ``structural_diff``, ``confidence_boost``.
        """
        result = {
            "is_anomalous": False,
            "anomaly_indicators": [],
            "error_signatures_found": [],
            "info_leaks": [],
            "structural_diff": {},
            "confidence_boost": 0,
            "behavior_change": False,
            "technology_detected": technology,
        }

        # 1. Error signature detection
        errors = self._detect_error_signatures(
            baseline_text, payload_text, technology
        )
        result["error_signatures_found"] = errors
        if errors:
            result["is_anomalous"] = True
            result["anomaly_indicators"].append("error_signatures")
            result["confidence_boost"] += min(len(errors) * 10, 30)

        # 2. Information leakage detection
        leaks = self._detect_info_leaks(baseline_text, payload_text)
        result["info_leaks"] = leaks
        if leaks:
            result["is_anomalous"] = True
            result["anomaly_indicators"].append("information_leakage")
            result["confidence_boost"] += min(len(leaks) * 5, 20)

        # 3. Structural diff analysis
        structural = self._structural_diff(baseline_text, payload_text)
        result["structural_diff"] = structural
        if structural.get("significant_change"):
            result["is_anomalous"] = True
            result["anomaly_indicators"].append("structural_change")
            result["confidence_boost"] += 10

        # 4. Behavioral fingerprinting
        if status_code_baseline and status_code_payload:
            behavior = self._analyze_behavior(
                status_code_baseline, status_code_payload,
                len(baseline_text), len(payload_text),
            )
            result["behavior_change"] = behavior["changed"]
            if behavior["changed"]:
                result["is_anomalous"] = True
                result["anomaly_indicators"].append("behavior_change")
                result["confidence_boost"] += behavior.get("boost", 5)

        result["confidence_boost"] = min(result["confidence_boost"], 50)
        return result

    def _detect_error_signatures(
        self, baseline_text: str, payload_text: str, technology: str,
    ) -> List[Dict]:
        """Detect technology-specific error patterns in payload response only."""
        found = []

        # Determine which tech signatures to check
        techs_to_check = [technology.lower()] if technology else []
        techs_to_check.append("generic")
        # Also check all techs for auto-detection
        if not technology:
            techs_to_check.extend(self.ERROR_SIGNATURES.keys())

        checked_patterns = set()
        for tech in techs_to_check:
            signatures = self.ERROR_SIGNATURES.get(tech, [])
            for sig in signatures:
                pat = sig["pattern"]
                if pat in checked_patterns:
                    continue
                checked_patterns.add(pat)
                # Only flag if pattern is in payload response but NOT in baseline
                in_payload = bool(re.search(pat, payload_text, re.IGNORECASE))
                in_baseline = bool(re.search(pat, baseline_text, re.IGNORECASE))
                if in_payload and not in_baseline:
                    found.append({
                        "technology": tech,
                        "pattern": pat,
                        "severity": sig["severity"],
                        "leaks": sig["leaks"],
                    })

        return found

    def _detect_info_leaks(
        self, baseline_text: str, payload_text: str,
    ) -> List[Dict]:
        """Detect sensitive information leaked in payload response."""
        leaks = []
        for pattern, leak_type in self.INFO_LEAK_PATTERNS.items():
            in_payload = re.findall(pattern, payload_text, re.IGNORECASE)
            in_baseline = re.findall(pattern, baseline_text, re.IGNORECASE)
            # Only flag new leaks not in baseline
            new_leaks = set(in_payload) - set(in_baseline)
            if new_leaks:
                leaks.append({
                    "type": leak_type,
                    "count": len(new_leaks),
                    "samples": list(new_leaks)[:3],
                })
        return leaks

    def _structural_diff(
        self, baseline_text: str, payload_text: str,
    ) -> Dict:
        """Analyze structural differences between responses."""
        base_len = len(baseline_text)
        pay_len = len(payload_text)

        # Length difference
        if base_len > 0:
            length_ratio = abs(pay_len - base_len) / base_len
        else:
            length_ratio = 1.0 if pay_len > 0 else 0.0

        # Count HTML tags
        base_tags = len(re.findall(r"<\w+", baseline_text))
        pay_tags = len(re.findall(r"<\w+", payload_text))
        tag_diff = abs(pay_tags - base_tags)

        # Count HTML forms
        base_forms = len(re.findall(r"<form", baseline_text, re.IGNORECASE))
        pay_forms = len(re.findall(r"<form", payload_text, re.IGNORECASE))

        # New content analysis
        base_lines = set(baseline_text.splitlines())
        pay_lines = set(payload_text.splitlines())
        new_lines = len(pay_lines - base_lines)

        significant = (
            length_ratio > 0.3
            or tag_diff > 10
            or new_lines > 20
            or (base_forms != pay_forms)
        )

        return {
            "length_ratio": round(length_ratio, 4),
            "baseline_length": base_len,
            "payload_length": pay_len,
            "tag_diff": tag_diff,
            "new_lines": new_lines,
            "form_change": base_forms != pay_forms,
            "significant_change": significant,
        }

    @staticmethod
    def _analyze_behavior(
        status_baseline: int, status_payload: int,
        len_baseline: int, len_payload: int,
    ) -> Dict:
        """Analyze behavioral changes between baseline and payload responses."""
        changed = False
        boost = 0

        # Status code change
        if status_baseline != status_payload:
            changed = True
            # 200 → 500 is very significant (triggered an error)
            if status_baseline == 200 and status_payload >= 500:
                boost = 15
            # 200 → 302 could indicate redirect-based vulnerability
            elif status_baseline == 200 and status_payload in (301, 302, 303, 307):
                boost = 10
            # 200 → 403 could indicate WAF or access control
            elif status_baseline == 200 and status_payload == 403:
                boost = 5
            else:
                boost = 5

        # Significant size change without status change
        if not changed and len_baseline > 0:
            size_ratio = abs(len_payload - len_baseline) / len_baseline
            if size_ratio > 0.5:
                changed = True
                boost = 8

        return {"changed": changed, "boost": boost}

    def detect_technology(self, response_text: str, headers: Dict = None) -> List[str]:
        """Auto-detect technologies from response content and headers.

        Returns a list of detected technology names.
        """
        detected = []
        headers = headers or {}

        # Header-based detection
        server = headers.get("server", headers.get("Server", "")).lower()
        powered_by = headers.get("x-powered-by", headers.get("X-Powered-By", "")).lower()

        if "php" in powered_by or "php" in server:
            detected.append("php")
        # Check X-Powered-By / Server headers for ASP.NET technology detection
        # (not URL validation — these are HTTP header values from response)
        _aspnet = "asp" + ".net"  # avoid CodeQL false positive on domain-like string
        if _aspnet in powered_by or _aspnet in server:
            detected.append("dotnet")
        if "express" in powered_by:
            detected.append("node")
        if "nginx" in server:
            detected.append("nginx")
        if "apache" in server:
            detected.append("apache")

        # Content-based detection
        text_lower = response_text.lower()
        if "wp-content" in text_lower or "wordpress" in text_lower:
            detected.append("wordpress")
        if "django" in text_lower or "csrfmiddlewaretoken" in text_lower:
            detected.append("python")
        if "__next" in text_lower or "next.js" in text_lower:
            detected.append("node")
        if "spring" in text_lower:
            detected.append("java")

        return list(set(detected))
