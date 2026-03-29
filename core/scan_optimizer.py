"""Dynamic Scan Optimizer — adaptive scan strategy engine.

Chimera Edition (v9.0) introduces dynamic scan optimization that adjusts
scanning strategy based on early reconnaissance results and discovered
patterns.  This reduces scan time while increasing coverage by focusing
resources on high-value targets.

Key capabilities:
- **Endpoint prioritization**: Ranks discovered endpoints by likely
  vulnerability density based on parameter count, technology hints,
  and URL patterns.
- **Redundancy elimination**: Identifies duplicate or near-duplicate
  endpoints and deduplicates them to avoid wasted effort.
- **Technology-aware module selection**: Recommends exploit modules
  based on detected technology stack.
- **Progressive depth adjustment**: Suggests increasing scan depth for
  endpoints that yield early findings.

For authorized security testing only.
"""
import logging
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

from config import SCAN_OPTIMIZATION_ENABLED, SCAN_OPTIMIZER_MIN_ENDPOINTS

logger = logging.getLogger("venomstrike.scan_optimizer")


# URL patterns that historically indicate higher vulnerability density
HIGH_VALUE_PATH_PATTERNS = [
    (r"/api/v?\d+/", 25, "API endpoint with versioning"),
    (r"/admin", 20, "Administrative interface"),
    (r"/auth|/login|/register|/signup", 18, "Authentication endpoint"),
    (r"/upload|/import|/file", 18, "File handling endpoint"),
    (r"/search|/query|/filter", 15, "Search/query endpoint"),
    (r"/user|/profile|/account", 15, "User data endpoint"),
    (r"/webhook|/callback|/notify", 15, "Callback endpoint"),
    (r"/export|/download|/report", 12, "Data export endpoint"),
    (r"/config|/settings|/preferences", 12, "Configuration endpoint"),
    (r"/graphql", 20, "GraphQL endpoint"),
    (r"/ws|/socket|/websocket", 15, "WebSocket endpoint"),
    (r"/redirect|/goto|/return", 12, "Redirect endpoint"),
    (r"/proxy|/fetch|/load", 18, "Proxy/fetch endpoint"),
    (r"/debug|/test|/dev", 20, "Debug/test endpoint"),
    (r"\.php$|\.asp$|\.jsp$", 10, "Server-side script extension"),
]

# Parameter names that suggest specific vulnerability types
PARAM_VULN_HINTS: Dict[str, List[str]] = {
    "sqli": ["id", "user_id", "item_id", "product_id", "category_id",
             "order_id", "page", "sort", "filter", "limit", "offset"],
    "xss": ["q", "query", "search", "keyword", "name", "title",
            "comment", "message", "body", "text", "content"],
    "ssrf": ["url", "uri", "link", "href", "src", "redirect",
             "return_url", "next", "dest", "callback", "webhook"],
    "lfi": ["file", "path", "page", "template", "include",
            "dir", "folder", "document", "lang", "locale"],
    "cmd": ["cmd", "command", "exec", "run", "ping",
            "host", "ip", "target"],
}

# Technology → recommended exploit modules
TECH_MODULE_MAP: Dict[str, List[str]] = {
    "php": ["sqli", "lfi", "rfi", "file_upload", "ssti", "cmd", "xxe"],
    "python": ["ssti", "sqli", "cmd", "deserialization"],
    "java": ["deserialization", "sqli", "xxe", "ssti", "cmd"],
    "node": ["nosql", "ssti", "prototype_pollution", "cmd", "ssrf"],
    "dotnet": ["sqli", "deserialization", "xxe", "lfi"],
    "wordpress": ["sqli", "xss", "file_upload", "lfi", "auth_bypass"],
    "graphql": ["graphql"],
    "mysql": ["sqli"],
    "postgresql": ["sqli"],
    "mongodb": ["nosql"],
}


class EndpointPriority:
    """Scored endpoint with priority metadata."""

    __slots__ = ("url", "method", "params", "score", "reasons",
                 "suggested_modules", "technology_hints")

    def __init__(self, url: str, method: str = "GET", params: List[str] = None):
        self.url = url
        self.method = method
        self.params = params or []
        self.score = 0.0
        self.reasons: List[str] = []
        self.suggested_modules: List[str] = []
        self.technology_hints: List[str] = []

    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "priority_score": round(self.score, 2),
            "reasons": self.reasons,
            "suggested_modules": self.suggested_modules,
            "technology_hints": self.technology_hints,
        }


class ScanOptimizer:
    """Dynamic scan strategy optimizer.

    Usage::

        optimizer = ScanOptimizer()
        result = optimizer.optimize(endpoints, technologies=["php", "mysql"])
        prioritized = result["prioritized_endpoints"]
        # Use prioritized list for scanning order
    """

    def __init__(self, enabled: bool = None):
        self._enabled = enabled if enabled is not None else SCAN_OPTIMIZATION_ENABLED

    @property
    def enabled(self) -> bool:
        return self._enabled

    def optimize(
        self,
        endpoints: List[Dict],
        technologies: List[str] = None,
        existing_findings: List[Dict] = None,
    ) -> Dict:
        """Optimize scan strategy based on discovered endpoints.

        Args:
            endpoints: List of endpoint dicts with ``url``, ``method``,
                ``params`` keys.
            technologies: Detected technology stack.
            existing_findings: Any findings already discovered.

        Returns:
            Dict with ``prioritized_endpoints``, ``deduplicated_count``,
            ``module_recommendations``, ``optimization_summary``.
        """
        if not self._enabled:
            return {
                "prioritized_endpoints": endpoints,
                "deduplicated_count": 0,
                "module_recommendations": [],
                "optimization_summary": {},
            }

        technologies = technologies or []

        # Step 1: Deduplicate endpoints
        unique_endpoints = self._deduplicate(endpoints)
        dedup_count = len(endpoints) - len(unique_endpoints)

        # Step 2: Score and prioritize
        scored = self._score_endpoints(unique_endpoints, technologies, existing_findings)

        # Step 3: Build module recommendations
        module_recs = self._recommend_modules(technologies, scored)

        # Step 4: Build summary
        summary = {
            "total_endpoints": len(endpoints),
            "unique_endpoints": len(unique_endpoints),
            "deduplicated": dedup_count,
            "high_priority_count": sum(1 for s in scored if s.score >= 50),
            "medium_priority_count": sum(1 for s in scored if 25 <= s.score < 50),
            "low_priority_count": sum(1 for s in scored if s.score < 25),
            "technologies_detected": technologies,
        }

        return {
            "prioritized_endpoints": [s.to_dict() for s in scored],
            "deduplicated_count": dedup_count,
            "module_recommendations": module_recs,
            "optimization_summary": summary,
        }

    def _deduplicate(self, endpoints: List[Dict]) -> List[Dict]:
        """Remove duplicate or near-duplicate endpoints."""
        seen: Set[str] = set()
        unique: List[Dict] = []

        for ep in endpoints:
            url = ep.get("url", "")
            method = ep.get("method", "GET")

            # Normalize: remove query string values, keep structure
            try:
                parsed = urlparse(url)
                params = sorted(parse_qs(parsed.query).keys())
                fingerprint = f"{method}|{parsed.netloc}{parsed.path}|{'&'.join(params)}"
            except Exception:
                fingerprint = f"{method}|{url}"

            if fingerprint not in seen:
                seen.add(fingerprint)
                unique.append(ep)

        return unique

    def _score_endpoints(
        self,
        endpoints: List[Dict],
        technologies: List[str],
        existing_findings: List[Dict] = None,
    ) -> List[EndpointPriority]:
        """Score endpoints by expected vulnerability density."""
        scored: List[EndpointPriority] = []
        finding_paths: Set[str] = set()

        if existing_findings:
            for f in existing_findings:
                try:
                    finding_paths.add(urlparse(f.get("url", "")).path)
                except Exception:
                    pass

        for ep in endpoints:
            url = ep.get("url", "")
            method = ep.get("method", "GET")
            params = ep.get("params", [])
            if isinstance(params, dict):
                params = list(params.keys())

            priority = EndpointPriority(url, method, params)

            # Score: parameter count
            param_count = len(params)
            if param_count > 0:
                priority.score += min(param_count * 5, 25)
                priority.reasons.append(f"{param_count} injectable parameters")

            # Score: POST method (more likely to have state-changing logic)
            if method.upper() == "POST":
                priority.score += 10
                priority.reasons.append("POST method (state-changing)")

            # Score: URL pattern matching
            try:
                path = urlparse(url).path
            except Exception:
                path = url
            for pattern, boost, desc in HIGH_VALUE_PATH_PATTERNS:
                if re.search(pattern, path, re.IGNORECASE):
                    priority.score += boost
                    priority.reasons.append(desc)
                    break  # Take highest-scoring match only

            # Score: parameter name hints
            suggested: Set[str] = set()
            for param in params:
                param_lower = param.lower() if isinstance(param, str) else ""
                for vuln_type, hint_params in PARAM_VULN_HINTS.items():
                    if param_lower in hint_params:
                        priority.score += 8
                        suggested.add(vuln_type)
                        break
            priority.suggested_modules = sorted(suggested)

            # Score: boost for paths near existing findings
            try:
                ep_path = urlparse(url).path
            except Exception:
                ep_path = ""
            if ep_path and ep_path in finding_paths:
                priority.score += 15
                priority.reasons.append("Near existing finding")

            # Technology hints
            priority.technology_hints = technologies

            scored.append(priority)

        scored.sort(key=lambda p: p.score, reverse=True)
        return scored

    def _recommend_modules(
        self,
        technologies: List[str],
        scored_endpoints: List[EndpointPriority],
    ) -> List[Dict]:
        """Recommend exploit modules based on technology and endpoints."""
        recommendations: List[Dict] = []
        seen_modules: Set[str] = set()

        # Technology-based recommendations
        for tech in technologies:
            tech_lower = tech.lower()
            modules = TECH_MODULE_MAP.get(tech_lower, [])
            for mod in modules:
                if mod not in seen_modules:
                    seen_modules.add(mod)
                    recommendations.append({
                        "module": mod,
                        "reason": f"Detected technology: {tech}",
                        "priority": "high",
                    })

        # Endpoint-based recommendations
        for ep in scored_endpoints[:20]:  # Top 20 endpoints
            for mod in ep.suggested_modules:
                if mod not in seen_modules:
                    seen_modules.add(mod)
                    recommendations.append({
                        "module": mod,
                        "reason": f"Parameter hints at {ep.url}",
                        "priority": "medium",
                    })

        return recommendations

    def adjust_depth_for_endpoint(
        self,
        endpoint: Dict,
        current_depth: str,
        finding_count: int,
    ) -> str:
        """Suggest depth adjustment based on finding density.

        If an endpoint is yielding findings, suggest deepening the scan.
        """
        depth_order = ["quick", "standard", "deep", "full",
                       "quantum", "titan", "hydra", "chimera"]
        try:
            current_idx = depth_order.index(current_depth)
        except ValueError:
            return current_depth

        if finding_count >= 3 and current_idx < len(depth_order) - 1:
            suggested = depth_order[current_idx + 1]
            logger.info(
                "Scan optimizer: endpoint %s yielded %d findings, "
                "suggesting depth escalation %s → %s",
                endpoint.get("url", ""), finding_count,
                current_depth, suggested,
            )
            return suggested

        return current_depth
