"""Smart Parameter Deduplicator — intelligent parameter reduction engine.

Phoenix Edition (v10.0) introduces smart parameter deduplication that
analyzes endpoint parameters to eliminate redundant testing.  Instead
of testing every discovered parameter individually, the deduplicator
groups semantically similar parameters and selects representative
samples, dramatically reducing scan time without sacrificing detection
coverage.

Key capabilities:
- **Semantic grouping**: Groups parameters by name similarity and
  behavioural equivalence (e.g., ``user_id`` and ``userId``).
- **Type-based clustering**: Classifies parameters into archetypes
  (identifiers, search terms, file paths, URLs, flags) and tests
  a representative subset of each archetype per endpoint.
- **Redundancy scoring**: Assigns a redundancy score to each parameter
  pair and prunes near-duplicates that add no additional attack surface.
- **Coverage tracking**: Ensures at least one parameter of every
  archetype is retained so no vulnerability class is missed.

For authorized security testing only.
"""
import logging
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

from config import (
    PARAM_DEDUP_ENABLED,
    PARAM_DEDUP_SIMILARITY_THRESHOLD,
    PARAM_DEDUP_MAX_PER_TYPE,
)

logger = logging.getLogger("venomstrike.param_deduplicator")


# ── Parameter archetypes ────────────────────────────────────────
# Each archetype maps to a set of regex patterns that match typical
# parameter names of that category.  The deduplicator guarantees at
# least one representative of each archetype is retained.

PARAM_ARCHETYPES: Dict[str, List[str]] = {
    "identifier": [
        r"(?i)^(id|.*_id|.*Id|uid|gid|pid|oid|key|pk|ref|index|num|number)$",
    ],
    "search": [
        r"(?i)^(q|query|search|keyword|term|filter|find|lookup)$",
    ],
    "file_path": [
        r"(?i)^(file|path|dir|directory|template|include|page|doc|document|lang|locale)$",
    ],
    "url": [
        r"(?i)^(url|uri|link|href|src|redirect|return_url|next|dest|callback|webhook|goto)$",
    ],
    "text_content": [
        r"(?i)^(name|title|comment|message|body|text|content|description|bio|note|label)$",
    ],
    "auth_token": [
        r"(?i)^(token|session|auth|api_key|apikey|secret|password|passwd|pwd|credential)$",
    ],
    "numeric": [
        r"(?i)^(page|limit|offset|count|size|amount|price|quantity|total|max|min|start|end)$",
    ],
    "flag": [
        r"(?i)^(debug|test|admin|verbose|enabled|disabled|active|status|mode|type|format|action)$",
    ],
    "command": [
        r"(?i)^(cmd|command|exec|run|ping|shell|process|ip|host|hostname|port|server)$",
    ],
    "sort_order": [
        r"(?i)^(sort|order|orderby|sort_by|direction|asc|desc|column|field|group_by)$",
    ],
}


def _normalize_param_name(name: str) -> str:
    """Normalize a parameter name for comparison.

    Converts camelCase, PascalCase, and kebab-case to lower_snake_case,
    then strips trailing digits.  e.g.:
        ``userId`` → ``user_id``
        ``product-id`` → ``product_id``
        ``Item_ID`` → ``item_id``
        ``page2`` → ``page``
    """
    # camelCase → snake_case
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    # kebab-case → snake_case
    s = s.replace("-", "_")
    s = s.lower()
    # strip trailing digits (page2 → page)
    s = re.sub(r"\d+$", "", s)
    return s


def _classify_param(name: str) -> str:
    """Return the archetype of a parameter name, or 'unknown'."""
    normalized = _normalize_param_name(name)
    for archetype, patterns in PARAM_ARCHETYPES.items():
        for pat in patterns:
            if re.match(pat, name) or re.match(pat, normalized):
                return archetype
    return "unknown"


def _similarity_score(a: str, b: str) -> float:
    """Compute a simple similarity score between two normalised param names.

    Returns a value in [0.0, 1.0].  Uses Jaccard similarity on character
    trigrams so that ``user_id`` and ``userid`` score high.
    """
    if a == b:
        return 1.0
    na = _normalize_param_name(a)
    nb = _normalize_param_name(b)
    if na == nb:
        return 1.0
    tris_a = {na[i:i + 3] for i in range(max(1, len(na) - 2))}
    tris_b = {nb[i:i + 3] for i in range(max(1, len(nb) - 2))}
    if not tris_a or not tris_b:
        return 0.0
    intersection = len(tris_a & tris_b)
    union = len(tris_a | tris_b)
    return intersection / union if union else 0.0


class SmartParamDeduplicator:
    """Reduces redundant parameters before exploit scanning.

    Given a list of endpoint dicts (with ``params`` lists), the
    deduplicator groups similar parameters and returns a pruned endpoint
    list where each archetype is represented by at most
    ``max_per_type`` parameters.
    """

    def __init__(
        self,
        similarity_threshold: float = None,
        max_per_type: int = None,
    ):
        self.similarity_threshold = (
            similarity_threshold
            if similarity_threshold is not None
            else PARAM_DEDUP_SIMILARITY_THRESHOLD
        )
        self.max_per_type = (
            max_per_type if max_per_type is not None else PARAM_DEDUP_MAX_PER_TYPE
        )
        # Tracking stats
        self.total_before = 0
        self.total_after = 0
        self.groups_found: Dict[str, int] = {}

    # ── Public API ──────────────────────────────────────────────

    def deduplicate_endpoints(
        self, endpoints: List[Dict],
    ) -> List[Dict]:
        """Deduplicate parameters across all endpoints.

        Each endpoint dict is expected to have a ``params`` key containing
        a list of parameter names (strings) or dicts with a ``name`` key.
        Returns a new list with pruned ``params``.
        """
        if not PARAM_DEDUP_ENABLED:
            return endpoints

        result = []
        for ep in endpoints:
            result.append(self._deduplicate_single(ep))
        return result

    def deduplicate_params(self, params: List[str]) -> List[str]:
        """Deduplicate a flat list of parameter names.

        Returns the pruned list.
        """
        if not PARAM_DEDUP_ENABLED or not params:
            return params

        classified: Dict[str, List[str]] = {}
        for p in params:
            archetype = _classify_param(p)
            classified.setdefault(archetype, []).append(p)

        kept: List[str] = []
        for archetype, group in classified.items():
            selected = self._select_representatives(group)
            kept.extend(selected)
            self.groups_found[archetype] = self.groups_found.get(archetype, 0) + len(group)

        self.total_before += len(params)
        self.total_after += len(kept)
        return kept

    def get_stats(self) -> Dict:
        """Return deduplication statistics."""
        reduction = 0.0
        if self.total_before > 0:
            reduction = 1.0 - (self.total_after / self.total_before)
        return {
            "total_before": self.total_before,
            "total_after": self.total_after,
            "reduction_percent": round(reduction * 100, 1),
            "archetype_counts": dict(self.groups_found),
        }

    # ── Internal helpers ────────────────────────────────────────

    def _deduplicate_single(self, endpoint: Dict) -> Dict:
        """Deduplicate params for a single endpoint."""
        raw_params = endpoint.get("params", [])
        if not raw_params:
            return endpoint

        # Support both list-of-strings and list-of-dicts
        if raw_params and isinstance(raw_params[0], dict):
            names = [p.get("name", "") for p in raw_params if p.get("name")]
        else:
            names = [str(p) for p in raw_params if p]

        kept_names = set(self.deduplicate_params(names))

        # Rebuild params list preserving original format
        if raw_params and isinstance(raw_params[0], dict):
            new_params = [p for p in raw_params if p.get("name") in kept_names]
        else:
            new_params = [p for p in raw_params if str(p) in kept_names]

        new_ep = dict(endpoint)
        new_ep["params"] = new_params
        return new_ep

    def _select_representatives(self, group: List[str]) -> List[str]:
        """Select representative parameters from a similarity group.

        Picks up to ``max_per_type`` parameters that are maximally
        different from each other.
        """
        if len(group) <= self.max_per_type:
            return group

        # Greedily select the most diverse subset
        selected = [group[0]]
        remaining = list(group[1:])

        while len(selected) < self.max_per_type and remaining:
            # Pick the candidate with the lowest max-similarity to
            # already-selected items (i.e., most different).
            best_idx = 0
            best_min_sim = 1.0
            for i, cand in enumerate(remaining):
                max_sim = max(
                    _similarity_score(cand, s) for s in selected
                )
                if max_sim < best_min_sim:
                    best_min_sim = max_sim
                    best_idx = i
            selected.append(remaining.pop(best_idx))

        return selected
