"""Smart Payload Selection Engine — context-aware payload prioritization.

Hydra Edition (v8.0) introduces intelligent payload selection that ranks
payloads by likelihood of success based on the target's technology stack,
parameter type, response behaviour patterns, and historical effectiveness.

Instead of spraying every payload blindly, the selector builds a priority
score for each payload and returns them in ranked order — hitting
high-probability payloads first.  This reduces noise, speeds up scans,
and increases the ratio of true positives.

For authorized security testing only.
"""
import logging
import re
from typing import Dict, List, Optional

logger = logging.getLogger("venomstrike.smart_selector")


class SmartPayloadSelector:
    """Rank and prioritize payloads based on context signals.

    Signals used for ranking:
    - **Technology match**: Payloads targeting the detected DB/framework score higher.
    - **Parameter type affinity**: SQLi payloads rank higher on ``id``-like params;
      XSS payloads rank higher on ``q``/``search`` params.
    - **Reflection context**: If the parameter reflects in HTML attributes, attribute-
      breakout payloads rank higher.
    - **WAF awareness**: If a WAF is detected, WAF-bypass variants rank higher.
    - **Historical success**: Payload categories that previously produced confirmed
      findings get a boost in subsequent tests.

    Usage::

        selector = SmartPayloadSelector()
        ranked = selector.prioritize(
            payloads=["' OR 1=1 --", "<script>alert(1)</script>", ...],
            context={"technology": "mysql", "param_name": "id",
                     "param_type": "query", "reflection_context": "none"},
        )
    """

    # Parameter name patterns that suggest specific vulnerability types
    PARAM_VULN_AFFINITY: Dict[str, List[str]] = {
        "sqli": [
            r"^id$", r"^user_?id$", r"^item_?id$", r"^product_?id$",
            r"^cat(egory)?_?id$", r"^order_?id$", r"^page$", r"^sort$",
            r"^filter$", r"^column$", r"^table$", r"^limit$", r"^offset$",
        ],
        "xss": [
            r"^q$", r"^query$", r"^search$", r"^keyword$", r"^name$",
            r"^title$", r"^comment$", r"^message$", r"^body$", r"^text$",
            r"^input$", r"^value$", r"^content$", r"^description$",
        ],
        "ssrf": [
            r"^url$", r"^uri$", r"^link$", r"^href$", r"^src$",
            r"^redirect$", r"^return_?url$", r"^next$", r"^dest$",
            r"^callback$", r"^webhook$", r"^feed$", r"^proxy$",
        ],
        "lfi": [
            r"^file$", r"^path$", r"^page$", r"^template$", r"^include$",
            r"^dir$", r"^folder$", r"^document$", r"^lang$", r"^locale$",
        ],
        "cmd": [
            r"^cmd$", r"^command$", r"^exec$", r"^run$", r"^ping$",
            r"^host$", r"^ip$", r"^target$", r"^daemon$",
        ],
        "ssti": [
            r"^template$", r"^name$", r"^email$", r"^subject$",
            r"^greeting$", r"^message$", r"^preview$",
        ],
    }

    # Technology → payload keyword boosts
    TECH_PAYLOAD_KEYWORDS: Dict[str, List[str]] = {
        "mysql": ["SLEEP", "BENCHMARK", "UNION", "information_schema", "/*!"],
        "postgresql": ["pg_sleep", "$$", "CAST", "string_agg", "chr("],
        "mssql": ["WAITFOR", "EXEC", "xp_cmdshell", "CHAR(", "sys."],
        "oracle": ["DUAL", "UTL_HTTP", "DBMS_PIPE", "CHR(", "ALL_TABLES"],
        "sqlite": ["sqlite_", "typeof(", "GLOB", "REPLACE(", "substr("],
        "php": ["php://", "filter/", "include", "require", "eval("],
        "jinja2": ["{{", "}}", "__class__", "__mro__", "__subclasses__"],
        "node": ["__proto__", "constructor", "require(", "process."],
        "java": ["Runtime", "ProcessBuilder", "ClassLoader", "java.lang"],
        "python": ["__import__", "os.system", "subprocess", "exec("],
    }

    # WAF bypass indicator keywords — payloads with these rank higher when WAF is detected
    WAF_BYPASS_INDICATORS = [
        "/*!", "%00", "%0d%0a", "/**/", "CHAR(", "CHR(",
        "0x", "CONCAT(", "\\u", "%c0%", "/**_**/",
        "case", "WHEN", "THEN", "ELSE",
    ]

    def __init__(self):
        self._success_history: Dict[str, int] = {}

    def prioritize(
        self,
        payloads: List[str],
        context: Optional[Dict] = None,
        vuln_type: str = "",
        max_payloads: int = 0,
    ) -> List[str]:
        """Rank payloads by likelihood of success and return sorted list.

        Args:
            payloads: List of payload strings.
            context: Injection context dict with keys like ``technology``,
                ``param_name``, ``param_type``, ``reflection_context``,
                ``waf_detected``.
            vuln_type: The vulnerability type being tested (e.g. "sqli").
            max_payloads: If >0, return only top N payloads.

        Returns:
            Payloads sorted from highest to lowest priority score.
        """
        context = context or {}
        scored = []
        for payload in payloads:
            score = self._score_payload(payload, context, vuln_type)
            scored.append((score, payload))

        # Sort by score descending, stable sort preserves original order for ties
        scored.sort(key=lambda x: x[0], reverse=True)

        result = [p for _, p in scored]
        if max_payloads > 0:
            result = result[:max_payloads]
        return result

    def _score_payload(self, payload: str, context: Dict, vuln_type: str) -> float:
        """Calculate priority score for a single payload."""
        score = 50.0  # Base score

        # 1. Technology match boost
        tech = context.get("technology", "").lower()
        if tech and tech in self.TECH_PAYLOAD_KEYWORDS:
            keywords = self.TECH_PAYLOAD_KEYWORDS[tech]
            matches = sum(1 for kw in keywords if kw.lower() in payload.lower())
            score += matches * 10  # +10 per keyword match

        # 2. Parameter name affinity
        param_name = context.get("param_name", "").lower()
        if param_name and vuln_type:
            patterns = self.PARAM_VULN_AFFINITY.get(vuln_type, [])
            for pat in patterns:
                if re.search(pat, param_name, re.IGNORECASE):
                    score += 15  # Strong affinity match
                    break

        # 3. WAF-aware boosting
        waf_detected = context.get("waf_detected", False)
        if waf_detected:
            waf_matches = sum(
                1 for ind in self.WAF_BYPASS_INDICATORS
                if ind.lower() in payload.lower()
            )
            score += waf_matches * 8  # WAF bypass techniques rank higher

        # 4. Reflection context matching
        reflection = context.get("reflection_context", "")
        if reflection == "attribute" and any(
            kw in payload for kw in ["onfocus", "onmouseover", "autofocus", 'onerror']
        ):
            score += 20
        elif reflection == "script" and any(
            kw in payload for kw in ["';", '";', "//", "\\n"]
        ):
            score += 20
        elif reflection == "tag_content" and any(
            kw in payload.lower() for kw in ["<script", "<img", "<svg", "<body"]
        ):
            score += 20

        # 5. Historical success boost
        payload_category = self._categorize_payload(payload)
        if payload_category in self._success_history:
            score += min(self._success_history[payload_category] * 5, 30)

        # 6. Complexity bonus — more sophisticated payloads slightly preferred
        if len(payload) > 20:
            score += 3
        if any(c in payload for c in ["||", "&&", "UNION", "SELECT"]):
            score += 5

        return score

    def record_success(self, payload: str) -> None:
        """Record a successful payload hit to boost future similar payloads."""
        category = self._categorize_payload(payload)
        self._success_history[category] = self._success_history.get(category, 0) + 1
        logger.debug("Smart selector: recorded success for category '%s'", category)

    def get_success_history(self) -> Dict[str, int]:
        """Return the current success history."""
        return dict(self._success_history)

    @staticmethod
    def _categorize_payload(payload: str) -> str:
        """Categorize a payload into a broad category for history tracking."""
        pl = payload.lower()
        if any(kw in pl for kw in ["select", "union", "sleep", "waitfor", "1=1", "or 1"]):
            return "sqli"
        if any(kw in pl for kw in ["<script", "onerror", "onload", "alert(", "javascript:"]):
            return "xss"
        if any(kw in pl for kw in ["../", "..\\", "etc/passwd", "php://"]):
            return "lfi"
        if any(kw in pl for kw in ["http://", "https://", "169.254", "127.0.0.1"]):
            return "ssrf"
        if any(kw in pl for kw in [";", "|", "&&", "$(", "`"]):
            return "cmd"
        if any(kw in pl for kw in ["{{", "}}", "${", "__class__"]):
            return "ssti"
        return "generic"
