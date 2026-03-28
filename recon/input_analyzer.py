"""Input analyzer — identify and categorize input vectors for testing."""
# For authorized security testing only.
import re
import urllib.parse
from typing import List, Dict
import requests
from core.utils import make_request


class InputAnalyzer:
    def __init__(self, session: requests.Session):
        self.session = session

    def analyze(self, endpoints: List[Dict]) -> List[Dict]:
        """Analyze all endpoints and classify their input vectors."""
        analyzed = []
        for ep in endpoints:
            vectors = self._classify_vectors(ep)
            analyzed.append({**ep, "vectors": vectors})
        return analyzed

    def _classify_vectors(self, endpoint: Dict) -> List[Dict]:
        """Classify input vectors for an endpoint."""
        vectors = []
        params = endpoint.get("params", [])
        method = endpoint.get("method", "GET").upper()
        url = endpoint.get("url", "")

        for param in params:
            vector_types = self._guess_param_type(param, url)
            vectors.append({
                "name": param,
                "method": method,
                "types": vector_types,
                "priority": self._calculate_priority(param, vector_types),
            })
        
        # URL path segments
        parsed = urllib.parse.urlparse(url)
        path_parts = [p for p in parsed.path.split("/") if p]
        for part in path_parts:
            if re.match(r'^\d+$', part):  # Numeric ID
                vectors.append({
                    "name": f"path:{part}",
                    "method": "PATH",
                    "types": ["idor", "sqli"],
                    "priority": 8,
                })
        
        return vectors

    def _guess_param_type(self, param: str, url: str) -> List[str]:
        """Guess vulnerability types relevant to parameter."""
        param_lower = param.lower()
        types = ["xss", "sqli"]  # Default for all params
        
        if any(k in param_lower for k in ["file", "path", "dir", "include", "load", "template", "page"]):
            types.extend(["lfi", "rfi", "ssrf"])
        if any(k in param_lower for k in ["url", "redirect", "return", "next", "goto", "link", "target"]):
            types.extend(["open_redirect", "ssrf"])
        if any(k in param_lower for k in ["id", "user_id", "uid", "pid", "order", "account"]):
            types.extend(["idor"])
        if any(k in param_lower for k in ["cmd", "exec", "command", "ping", "host", "query"]):
            types.extend(["cmd"])
        if any(k in param_lower for k in ["template", "view", "theme", "layout", "render"]):
            types.extend(["ssti"])
        if any(k in param_lower for k in ["search", "q", "s", "find", "filter"]):
            types.extend(["nosql"])
        if any(k in param_lower for k in ["xml", "data", "payload", "input"]):
            types.extend(["xxe"])
        if any(k in param_lower for k in ["user", "username", "login", "email"]):
            types.extend(["ldap", "xpath"])
        
        return list(set(types))

    def _calculate_priority(self, param: str, types: List[str]) -> int:
        """Calculate testing priority (1-10)."""
        high_priority_types = {"cmd", "lfi", "ssrf", "rce", "xxe"}
        if high_priority_types.intersection(set(types)):
            return 9
        if "sqli" in types and any(k in param.lower() for k in ["id", "user", "pass"]):
            return 8
        return 5
