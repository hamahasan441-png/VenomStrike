"""Vulnerability Impact Analyzer — real-world exploitability rating.

Phoenix Edition (v10.0) introduces impact analysis that goes beyond
CVSS-like static scoring to assess the real-world exploitability of
each finding.

Key capabilities:
- **Exploitability assessment**: Rates how likely the vulnerability is
  to be successfully exploited in practice (not just theoretically).
- **Business impact estimation**: Considers the type of data/operation
  at risk based on the endpoint and parameter context.
- **Attack complexity scoring**: Evaluates the effort required to
  exploit, including authentication requirements, WAF presence, and
  multi-step prerequisites.
- **Remediation priority**: Combines exploitability and impact to
  suggest a prioritised fix order.

For authorized security testing only.
"""
import logging
import re
from typing import Dict, List, Optional

from config import IMPACT_ANALYSIS_ENABLED

logger = logging.getLogger("venomstrike.impact_analyzer")


# ── Exploitability factors ─────────────────────────────────────

# Base exploitability by vulnerability type (0-100)
VULN_EXPLOITABILITY: Dict[str, int] = {
    "SQL Injection": 95,
    "SQL Injection (Error-Based)": 95,
    "SQL Injection (Boolean Blind)": 80,
    "SQL Injection (Time-Based Blind)": 75,
    "SQL Injection (UNION)": 90,
    "Command Injection": 98,
    "Command Injection (Blind)": 80,
    "XSS (Reflected)": 70,
    "XSS (Stored)": 85,
    "XSS (DOM-Based)": 65,
    "SSRF": 85,
    "SSRF (Blind)": 70,
    "LFI": 80,
    "RFI": 90,
    "SSTI": 90,
    "XXE": 85,
    "XXE (Blind)": 70,
    "CSRF": 60,
    "IDOR": 75,
    "JWT Vulnerability": 80,
    "Auth Bypass": 95,
    "File Upload": 85,
    "RCE": 98,
    "Deserialization": 90,
    "Prototype Pollution": 65,
    "GraphQL Injection": 75,
    "Cache Poisoning": 70,
    "HTTP Smuggling": 80,
    "CRLF Injection": 60,
    "Host Header Injection": 65,
    "Open Redirect": 50,
    "Clickjacking": 40,
    "CORS Misconfiguration": 55,
    "Parameter Tampering": 70,
    "Mass Assignment": 75,
    "Race Condition": 65,
    "Account Takeover": 95,
    "NoSQL Injection": 85,
    "LDAP Injection": 80,
    "XPath Injection": 75,
    "Subdomain Takeover": 70,
    "API Key Exposure": 80,
    "HTTP/2 Desync": 75,
    "WebSocket Vulnerability": 65,
}

# Data sensitivity hints by URL/parameter pattern
DATA_SENSITIVITY_PATTERNS: List[Dict] = [
    {"pattern": r"(?i)(password|passwd|pwd|secret|credential|token)",
     "sensitivity": "critical", "score": 100},
    {"pattern": r"(?i)(credit.?card|cc_num|cvv|ssn|social.?security)",
     "sensitivity": "critical", "score": 100},
    {"pattern": r"(?i)(email|phone|address|dob|birth|medical|health)",
     "sensitivity": "high", "score": 80},
    {"pattern": r"(?i)(user|account|profile|name|identity)",
     "sensitivity": "high", "score": 70},
    {"pattern": r"(?i)(payment|billing|order|transaction|invoice)",
     "sensitivity": "high", "score": 80},
    {"pattern": r"(?i)(admin|config|setting|permission|role|privilege)",
     "sensitivity": "high", "score": 75},
    {"pattern": r"(?i)(api|key|auth|session|jwt|oauth)",
     "sensitivity": "high", "score": 75},
    {"pattern": r"(?i)(file|upload|document|attachment|media)",
     "sensitivity": "medium", "score": 60},
    {"pattern": r"(?i)(search|query|filter|sort|page|limit)",
     "sensitivity": "low", "score": 30},
    {"pattern": r"(?i)(debug|test|dev|staging|sandbox)",
     "sensitivity": "medium", "score": 50},
]


# Attack complexity modifiers
COMPLEXITY_MODIFIERS: Dict[str, int] = {
    "requires_authentication": -15,
    "waf_detected": -10,
    "multi_step_required": -20,
    "time_based_only": -10,
    "blind_only": -15,
    "requires_user_interaction": -10,
    "direct_exploitation": 10,
    "no_auth_required": 10,
    "error_messages_visible": 15,
}


class ImpactAnalyzer:
    """Assesses real-world exploitability and business impact of findings.

    Produces a prioritised list of findings with exploitability ratings
    and remediation ordering.
    """

    def __init__(self):
        self.analyzed_count = 0

    # ── Public API ──────────────────────────────────────────────

    def analyze_finding(
        self,
        finding: Dict,
        waf_detected: bool = False,
        auth_required: bool = False,
    ) -> Dict:
        """Analyse the impact of a single finding.

        Returns the finding enriched with an ``impact_analysis`` field.
        """
        if not IMPACT_ANALYSIS_ENABLED:
            return finding

        self.analyzed_count += 1
        vuln_type = finding.get("vuln_type", "")
        url = finding.get("url", "")
        param = finding.get("param", "")
        confidence = finding.get("confidence", 50)

        # 1. Base exploitability
        base_exploitability = self._get_base_exploitability(vuln_type)

        # 2. Complexity modifiers
        modifiers = self._compute_complexity(
            vuln_type, waf_detected, auth_required
        )
        adjusted_exploitability = max(
            0, min(100, base_exploitability + modifiers)
        )

        # 3. Data sensitivity
        sensitivity = self._assess_data_sensitivity(url, param, vuln_type)

        # 4. Combined impact score
        impact_score = self._compute_impact_score(
            adjusted_exploitability, sensitivity["score"], confidence,
        )

        # 5. Remediation priority
        priority = self._compute_priority(impact_score)

        analysis = {
            "exploitability": adjusted_exploitability,
            "data_sensitivity": sensitivity["sensitivity"],
            "data_sensitivity_score": sensitivity["score"],
            "complexity_modifiers": modifiers,
            "impact_score": impact_score,
            "remediation_priority": priority,
            "priority_rank": self._priority_rank(priority),
        }

        finding = dict(finding)
        finding["impact_analysis"] = analysis
        return finding

    def analyze_findings(
        self,
        findings: List[Dict],
        waf_detected: bool = False,
        auth_required: bool = False,
    ) -> List[Dict]:
        """Analyse and prioritise a list of findings.

        Returns findings enriched with impact analysis, sorted by
        remediation priority (highest impact first).
        """
        if not IMPACT_ANALYSIS_ENABLED:
            return findings

        analyzed = [
            self.analyze_finding(f, waf_detected, auth_required)
            for f in findings
        ]
        # Sort by impact score descending
        analyzed.sort(
            key=lambda f: f.get("impact_analysis", {}).get("impact_score", 0),
            reverse=True,
        )
        return analyzed

    def get_stats(self) -> Dict:
        """Return analysis statistics."""
        return {"analyzed_count": self.analyzed_count}

    # ── Internal helpers ────────────────────────────────────────

    @staticmethod
    def _get_base_exploitability(vuln_type: str) -> int:
        """Look up base exploitability for a vulnerability type."""
        # Try exact match first
        if vuln_type in VULN_EXPLOITABILITY:
            return VULN_EXPLOITABILITY[vuln_type]
        # Try partial match
        vuln_lower = vuln_type.lower()
        for key, score in VULN_EXPLOITABILITY.items():
            if key.lower() in vuln_lower or vuln_lower in key.lower():
                return score
        return 50  # Default moderate exploitability

    @staticmethod
    def _compute_complexity(
        vuln_type: str, waf_detected: bool, auth_required: bool,
    ) -> int:
        """Compute complexity modifier sum."""
        modifiers = 0
        vuln_lower = vuln_type.lower()

        if auth_required:
            modifiers += COMPLEXITY_MODIFIERS["requires_authentication"]
        else:
            modifiers += COMPLEXITY_MODIFIERS["no_auth_required"]

        if waf_detected:
            modifiers += COMPLEXITY_MODIFIERS["waf_detected"]

        if "blind" in vuln_lower:
            modifiers += COMPLEXITY_MODIFIERS["blind_only"]

        if "time" in vuln_lower:
            modifiers += COMPLEXITY_MODIFIERS["time_based_only"]

        if "error" in vuln_lower:
            modifiers += COMPLEXITY_MODIFIERS["error_messages_visible"]

        if vuln_lower in ("csrf", "clickjacking", "open redirect"):
            modifiers += COMPLEXITY_MODIFIERS["requires_user_interaction"]

        return modifiers

    @staticmethod
    def _assess_data_sensitivity(
        url: str, param: str, vuln_type: str,
    ) -> Dict:
        """Assess data sensitivity based on URL and parameter context."""
        combined = f"{url} {param} {vuln_type}"
        best = {"sensitivity": "low", "score": 20}
        for entry in DATA_SENSITIVITY_PATTERNS:
            if re.search(entry["pattern"], combined):
                if entry["score"] > best["score"]:
                    best = {
                        "sensitivity": entry["sensitivity"],
                        "score": entry["score"],
                    }
        return best

    @staticmethod
    def _compute_impact_score(
        exploitability: int, sensitivity_score: int, confidence: int,
    ) -> int:
        """Compute the combined impact score (0-100)."""
        # Weighted combination: exploitability 40%, sensitivity 35%, confidence 25%
        raw = (exploitability * 0.40) + (sensitivity_score * 0.35) + (confidence * 0.25)
        return max(0, min(100, round(raw)))

    @staticmethod
    def _compute_priority(impact_score: int) -> str:
        """Map impact score to remediation priority label."""
        if impact_score >= 80:
            return "P0-Critical"
        elif impact_score >= 60:
            return "P1-High"
        elif impact_score >= 40:
            return "P2-Medium"
        elif impact_score >= 20:
            return "P3-Low"
        else:
            return "P4-Info"

    @staticmethod
    def _priority_rank(priority: str) -> int:
        """Numeric rank for sorting (lower = higher priority)."""
        ranks = {
            "P0-Critical": 0,
            "P1-High": 1,
            "P2-Medium": 2,
            "P3-Low": 3,
            "P4-Info": 4,
        }
        return ranks.get(priority, 5)
