"""Intelligent Payload Minimizer — coverage-aware payload reduction.

Phoenix Edition (v10.0) introduces a payload minimizer that analyses
payload sets and selects an optimal subset that maintains detection
coverage while significantly reducing scan time.

Key capabilities:
- **Coverage-based selection**: Groups payloads by the vulnerability
  class they detect (error-based, blind, time-based, etc.) and ensures
  each class has representative payloads.
- **Similarity pruning**: Removes near-duplicate payloads using
  structural fingerprinting — e.g., ``' OR 1=1--`` and ``' OR 2=2--``
  are treated as structurally equivalent.
- **Effectiveness ranking**: Prioritises payloads with broader
  detection capability (those that detect multiple vulnerability
  subclasses simultaneously).
- **Diminishing returns detection**: Stops adding payloads once the
  marginal detection gain drops below a threshold.

For authorized security testing only.
"""
import hashlib
import logging
import re
from typing import Dict, List, Optional, Set, Tuple

from config import (
    PAYLOAD_MINIMIZER_ENABLED,
    PAYLOAD_MINIMIZER_MAX_RATIO,
    PAYLOAD_MINIMIZER_MIN_PAYLOADS,
)

logger = logging.getLogger("venomstrike.payload_minimizer")


# ── Payload structural categories ──────────────────────────────
# Patterns that classify payloads into detection-strategy categories.
# The minimizer ensures at least one payload from each relevant
# category is present.

PAYLOAD_CATEGORIES: Dict[str, List[str]] = {
    # SQLi categories
    "sqli_error": [
        r"(?i)(syntax|error|warning|mysql|postgresql|sqlite|oracle|mssql)",
        r"['\"].*?(OR|AND)\s+\d",
    ],
    "sqli_union": [
        r"(?i)UNION\s+(ALL\s+)?SELECT",
    ],
    "sqli_boolean": [
        r"(?i)(OR\s+\d+=\d+|AND\s+\d+=\d+|OR\s+['\"].*?['\"]=['\"])",
    ],
    "sqli_time": [
        r"(?i)(SLEEP|WAITFOR|DELAY|BENCHMARK|pg_sleep)",
    ],
    "sqli_stacked": [
        r"(?i);\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)",
    ],
    # XSS categories
    "xss_script": [
        r"<script",
    ],
    "xss_event": [
        r"(?i)on(error|load|click|mouseover|focus)=",
    ],
    "xss_svg": [
        r"<svg",
    ],
    "xss_img": [
        r"<img",
    ],
    "xss_polyglot": [
        r"(?i)javascript:",
    ],
    # Command injection
    "cmd_pipe": [
        r"\|",
    ],
    "cmd_semicolon": [
        r";",
    ],
    "cmd_backtick": [
        r"`",
    ],
    "cmd_subshell": [
        r"\$\(",
    ],
    # SSTI
    "ssti_jinja": [
        r"\{\{.*\}\}",
    ],
    "ssti_mako": [
        r"\$\{.*\}",
    ],
    # Path traversal
    "traversal_unix": [
        r"\.\./",
    ],
    "traversal_windows": [
        r"\.\\.\\",
    ],
    "traversal_null": [
        r"%00",
    ],
    # SSRF
    "ssrf_localhost": [
        r"(?i)(127\.0\.0\.1|localhost|0\.0\.0\.0)",
    ],
    "ssrf_cloud": [
        r"169\.254\.169\.254",
    ],
}


def _structural_fingerprint(payload: str) -> str:
    """Generate a structural fingerprint for a payload.

    Replaces specific values with placeholders to identify structurally
    equivalent payloads.  E.g.:
        ``' OR 1=1--`` → ``' OR {N}={N}--``
        ``<script>alert(1)</script>`` → ``<script>alert({N})</script>``
    """
    s = payload
    # Replace numbers
    s = re.sub(r"\d+", "{N}", s)
    # Replace quoted strings
    s = re.sub(r"'[^']*'", "'{S}'", s)
    s = re.sub(r'"[^"]*"', '"{S}"', s)
    # Replace hex values
    s = re.sub(r"0x[0-9a-fA-F]+", "{HEX}", s)
    # Replace common function arguments
    s = re.sub(r"\(.*?\)", "({A})", s)
    return hashlib.md5(s.encode()).hexdigest()[:12]


def _classify_payload(payload: str) -> Set[str]:
    """Return the set of categories a payload belongs to."""
    categories = set()
    for cat, patterns in PAYLOAD_CATEGORIES.items():
        for pat in patterns:
            if re.search(pat, payload):
                categories.add(cat)
                break
    return categories


class PayloadMinimizer:
    """Selects an optimal subset of payloads for maximum coverage.

    Given a list of payloads, the minimizer groups them by structural
    fingerprint and detection category, then selects the minimum set
    that covers all discovered categories.
    """

    def __init__(
        self,
        max_ratio: float = None,
        min_payloads: int = None,
    ):
        self.max_ratio = (
            max_ratio if max_ratio is not None else PAYLOAD_MINIMIZER_MAX_RATIO
        )
        self.min_payloads = (
            min_payloads if min_payloads is not None else PAYLOAD_MINIMIZER_MIN_PAYLOADS
        )
        # Stats
        self.total_before = 0
        self.total_after = 0

    # ── Public API ──────────────────────────────────────────────

    def minimize(
        self,
        payloads: List[str],
        vuln_type: str = "",
    ) -> List[str]:
        """Select the minimal effective payload subset.

        Returns a list of payloads that covers all detected categories.
        """
        if not PAYLOAD_MINIMIZER_ENABLED:
            return payloads

        if not payloads:
            return payloads

        self.total_before += len(payloads)

        # Step 1: Classify each payload
        payload_cats: List[Tuple[str, Set[str], str]] = []
        for p in payloads:
            cats = _classify_payload(p)
            fp = _structural_fingerprint(p)
            payload_cats.append((p, cats, fp))

        # Step 2: Deduplicate by structural fingerprint
        seen_fps: Set[str] = set()
        unique: List[Tuple[str, Set[str]]] = []
        for p, cats, fp in payload_cats:
            if fp not in seen_fps:
                seen_fps.add(fp)
                unique.append((p, cats))

        # Step 3: Greedy set-cover — pick payloads that maximise category coverage
        all_categories = set()
        for _, cats in unique:
            all_categories |= cats

        covered: Set[str] = set()
        selected: List[str] = []

        # Sort by category count descending (broadest coverage first)
        remaining = sorted(unique, key=lambda x: len(x[1]), reverse=True)

        while covered != all_categories and remaining:
            best_idx = 0
            best_gain = 0
            for i, (p, cats) in enumerate(remaining):
                gain = len(cats - covered)
                if gain > best_gain:
                    best_gain = gain
                    best_idx = i
            if best_gain == 0:
                break
            p, cats = remaining.pop(best_idx)
            selected.append(p)
            covered |= cats

        # Step 4: Ensure minimum payload count
        for p, cats in remaining:
            if len(selected) >= max(self.min_payloads, int(len(payloads) * self.max_ratio)):
                break
            if p not in selected:
                selected.append(p)

        # Ensure at least min_payloads
        if len(selected) < self.min_payloads:
            for p, cats in remaining:
                if p not in selected:
                    selected.append(p)
                if len(selected) >= self.min_payloads:
                    break

        self.total_after += len(selected)
        logger.debug(
            "Minimized %d → %d payloads (%d categories covered)",
            len(payloads), len(selected), len(covered),
        )
        return selected

    def get_stats(self) -> Dict:
        """Return minimization statistics."""
        reduction = 0.0
        if self.total_before > 0:
            reduction = 1.0 - (self.total_after / self.total_before)
        return {
            "total_before": self.total_before,
            "total_after": self.total_after,
            "reduction_percent": round(reduction * 100, 1),
        }
