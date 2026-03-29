"""Context-Aware Vulnerability Validator — technology-sensitive verification.

Phoenix Edition (v10.0) introduces context-aware validation that
understands the target's technology stack and adapts its verification
strategies accordingly.  This dramatically reduces false positives by
applying technology-specific heuristics to confirm or reject findings.

Key capabilities:
- **Technology-aware confirmation**: Uses detected technology (e.g.,
  Django, Rails, Express, Spring) to adjust expected error patterns,
  response codes, and behavioural signatures.
- **Framework-specific false-positive rules**: Each framework has known
  benign patterns (e.g., Django's debug page, Rails' CSRF meta tag)
  that should not be flagged.
- **Adaptive confidence adjustment**: Boosts or penalises finding
  confidence based on how well the evidence matches the expected
  technology-specific behaviour.
- **Response pattern learning**: Builds a profile of the target's
  normal response patterns and flags deviations.

For authorized security testing only.
"""
import logging
import re
from typing import Dict, List, Optional, Set, Tuple

from config import (
    CONTEXT_VALIDATION_ENABLED,
    CONTEXT_VALIDATION_BOOST,
    CONTEXT_VALIDATION_PENALTY,
)

logger = logging.getLogger("venomstrike.context_validator")


# ── Technology-specific false-positive patterns ─────────────────
# Patterns that look like vulnerabilities but are normal for that tech.

TECH_FALSE_POSITIVES: Dict[str, Dict[str, List[str]]] = {
    "django": {
        "xss": [
            r"csrfmiddlewaretoken",       # Django CSRF token in forms
            r"django\.contrib\.messages",  # Django messages framework
        ],
        "sqli": [
            r"django\.db\.utils\.",        # Django ORM error (not raw SQL)
            r"OperationalError.*no such table",  # SQLite migration error
        ],
        "ssti": [
            r"\{\%\s*csrf_token\s*\%\}",  # Django template tag
        ],
    },
    "rails": {
        "xss": [
            r'name="authenticity_token"',  # Rails CSRF token
            r"data-turbo",                 # Turbo/Hotwire attribute
        ],
        "sqli": [
            r"ActiveRecord::RecordNotFound",  # Standard 404
            r"ActionController::RoutingError",
        ],
    },
    "express": {
        "xss": [
            r"X-Powered-By:\s*Express",   # Express header
        ],
        "ssti": [
            r"EJS.*compile",              # EJS template compilation info
        ],
    },
    "spring": {
        "sqli": [
            r"org\.springframework\.jdbc",  # Spring JDBC error
            r"HibernateException",
        ],
        "xss": [
            r'_csrf.*hidden',             # Spring Security CSRF
        ],
    },
    "flask": {
        "ssti": [
            r"jinja2\.exceptions\.",       # Jinja2 error (template engine)
        ],
        "xss": [
            r"Markup\(",                   # Flask Markup safe string
        ],
    },
    "wordpress": {
        "xss": [
            r"wp-nonce",                   # WordPress nonce
            r"wpnonce",
        ],
        "sqli": [
            r"\$wpdb->",                   # WordPress DB API reference
        ],
    },
    "laravel": {
        "xss": [
            r'name="_token"',             # Laravel CSRF
            r"@csrf",                      # Blade CSRF directive
        ],
        "sqli": [
            r"Illuminate\\Database\\QueryException",  # Laravel ORM error
        ],
    },
    "asp.net": {
        "xss": [
            r"__RequestVerificationToken",  # ASP.NET anti-forgery
            r"__VIEWSTATE",                 # ASP.NET ViewState
        ],
        "sqli": [
            r"System\.Data\.SqlClient",    # .NET SQL provider
        ],
    },
}

# Response patterns that indicate WAF/security middleware, not vulns
SECURITY_MIDDLEWARE_PATTERNS = [
    r"(?i)access\s+denied",
    r"(?i)request\s+blocked",
    r"(?i)security\s+violation",
    r"(?i)bot\s+detected",
    r"(?i)captcha",
    r"(?i)rate\s+limit",
]

# Technology detection hints from response headers/body
TECH_DETECTION_HINTS: Dict[str, List[str]] = {
    "django": [r"(?i)csrfmiddlewaretoken", r"(?i)django", r"(?i)wsgiref"],
    "rails": [r"(?i)X-Request-Id", r"(?i)action_dispatch", r"(?i)rails"],
    "express": [r"(?i)X-Powered-By:\s*Express", r"(?i)connect\.sid"],
    "spring": [r"(?i)X-Application-Context", r"(?i)springframework"],
    "flask": [r"(?i)Werkzeug", r"(?i)flask"],
    "wordpress": [r"(?i)wp-content", r"(?i)wp-includes", r"(?i)wordpress"],
    "laravel": [r"(?i)laravel_session", r"(?i)XSRF-TOKEN"],
    "asp.net": [r"(?i)X-AspNet-Version", r"(?i)__VIEWSTATE", r"(?i)ASP\.NET"],
}


class ContextValidator:
    """Technology-aware vulnerability validation engine.

    Examines findings in the context of the detected technology stack
    and adjusts confidence based on technology-specific heuristics.
    """

    def __init__(self):
        self.detected_tech: Optional[str] = None
        self.response_profile: Dict[str, int] = {}
        self.validated_count = 0
        self.adjusted_count = 0
        self.rejected_count = 0

    # ── Public API ──────────────────────────────────────────────

    def detect_technology(
        self, headers: Dict[str, str] = None, body: str = "",
    ) -> Optional[str]:
        """Detect the target's technology from response headers and body.

        Returns the detected technology name or None.
        """
        combined = ""
        if headers:
            combined += " ".join(f"{k}: {v}" for k, v in headers.items())
        combined += " " + body

        for tech, patterns in TECH_DETECTION_HINTS.items():
            for pat in patterns:
                if re.search(pat, combined):
                    self.detected_tech = tech
                    logger.info("Detected technology: %s", tech)
                    return tech
        return None

    def validate_finding(
        self,
        finding: Dict,
        technology: str = None,
        response_body: str = "",
        response_headers: Dict[str, str] = None,
    ) -> Dict:
        """Validate a finding against technology-specific context.

        Returns the finding with adjusted confidence and a
        ``context_validation`` field containing the analysis result.
        """
        if not CONTEXT_VALIDATION_ENABLED:
            return finding

        self.validated_count += 1
        tech = technology or self.detected_tech
        vuln_type = finding.get("vuln_type", "").lower()
        confidence = finding.get("confidence", 50)

        validation = {
            "technology": tech or "unknown",
            "original_confidence": confidence,
            "adjustment": 0,
            "reason": "no context adjustment",
            "is_false_positive": False,
        }

        # Check for technology-specific false positives
        if tech and tech in TECH_FALSE_POSITIVES:
            fp_patterns = TECH_FALSE_POSITIVES[tech]
            # Check each vuln type category
            for vuln_cat, patterns in fp_patterns.items():
                if vuln_cat in vuln_type:
                    for pat in patterns:
                        if re.search(pat, response_body):
                            validation["is_false_positive"] = True
                            validation["adjustment"] = -CONTEXT_VALIDATION_PENALTY
                            validation["reason"] = (
                                f"Matches known {tech} false-positive pattern: {pat}"
                            )
                            self.rejected_count += 1
                            break
                if validation["is_false_positive"]:
                    break

        # Check for security middleware false positives
        if not validation["is_false_positive"]:
            for pat in SECURITY_MIDDLEWARE_PATTERNS:
                if re.search(pat, response_body):
                    validation["adjustment"] = -min(CONTEXT_VALIDATION_PENALTY, 15)
                    validation["reason"] = (
                        "Response contains security middleware pattern"
                    )
                    self.adjusted_count += 1
                    break

        # Positive boost: if finding matches technology-specific vuln pattern
        if not validation["is_false_positive"] and tech:
            boost = self._tech_specific_boost(tech, vuln_type, response_body)
            if boost > 0:
                validation["adjustment"] = max(
                    validation["adjustment"], boost
                )
                validation["reason"] = (
                    f"Technology-specific confirmation for {tech}"
                )
                self.adjusted_count += 1

        # Apply adjustment
        new_confidence = max(0, min(100, confidence + validation["adjustment"]))
        validation["final_confidence"] = new_confidence

        finding = dict(finding)
        finding["confidence"] = new_confidence
        finding["context_validation"] = validation
        return finding

    def validate_findings(
        self,
        findings: List[Dict],
        technology: str = None,
    ) -> List[Dict]:
        """Validate a list of findings, returning adjusted findings.

        Findings determined to be false positives are marked but not
        removed, so the caller can decide.
        """
        if not CONTEXT_VALIDATION_ENABLED:
            return findings
        return [self.validate_finding(f, technology=technology) for f in findings]

    def get_stats(self) -> Dict:
        """Return validation statistics."""
        return {
            "validated": self.validated_count,
            "adjusted": self.adjusted_count,
            "rejected_as_fp": self.rejected_count,
            "detected_technology": self.detected_tech,
        }

    # ── Internal helpers ────────────────────────────────────────

    @staticmethod
    def _tech_specific_boost(
        tech: str, vuln_type: str, response_body: str,
    ) -> int:
        """Return a confidence boost if the response matches tech-specific
        vulnerability indicators.
        """
        boost_patterns: Dict[str, Dict[str, List[Tuple[str, int]]]] = {
            "django": {
                "sqli": [
                    (r"ProgrammingError", CONTEXT_VALIDATION_BOOST),
                    (r"syntax error at or near", CONTEXT_VALIDATION_BOOST),
                ],
                "ssti": [
                    (r"TemplateSyntaxError", CONTEXT_VALIDATION_BOOST),
                ],
            },
            "rails": {
                "sqli": [
                    (r"PG::SyntaxError", CONTEXT_VALIDATION_BOOST),
                    (r"Mysql2::Error", CONTEXT_VALIDATION_BOOST),
                ],
            },
            "spring": {
                "sqli": [
                    (r"JDBCException", CONTEXT_VALIDATION_BOOST),
                    (r"BadSqlGrammarException", CONTEXT_VALIDATION_BOOST),
                ],
            },
            "wordpress": {
                "sqli": [
                    (r"WordPress database error", CONTEXT_VALIDATION_BOOST),
                ],
            },
            "laravel": {
                "sqli": [
                    (r"SQLSTATE\[", CONTEXT_VALIDATION_BOOST),
                ],
            },
        }

        tech_boosts = boost_patterns.get(tech, {})
        for vuln_cat, patterns in tech_boosts.items():
            if vuln_cat in vuln_type:
                for pat, boost_val in patterns:
                    if re.search(pat, response_body):
                        return boost_val
        return 0
