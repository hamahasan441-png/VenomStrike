"""Parameter extractor — GET/POST/JSON/header parameter discovery."""
# For authorized security testing only.
import os
import re
import json
import urllib.parse
from typing import List, Dict
import requests
from core.utils import make_request, load_payloads
from core.logger import log_info

HIDDEN_PARAMS_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists", "hidden_params.txt")


class ParamExtractor:
    def __init__(self, session: requests.Session):
        self.session = session

    def extract_from_url(self, url: str) -> List[str]:
        """Extract parameters from URL query string."""
        parsed = urllib.parse.urlparse(url)
        return list(urllib.parse.parse_qs(parsed.query).keys())

    def extract_from_response(self, response: requests.Response, url: str) -> Dict:
        """Extract parameters visible in response (forms, JS, JSON)."""
        params = {
            "get": self.extract_from_url(url),
            "post": [],
            "json": [],
            "headers": [],
        }
        if response is None:
            return params

        # Extract form fields
        from core.utils import extract_forms
        forms = extract_forms(response.text, url)
        for form in forms:
            for inp in form.get("inputs", []):
                if inp["name"] not in params["post"]:
                    params["post"].append(inp["name"])

        # Extract from JSON response
        ct = response.headers.get("Content-Type", "")
        if "json" in ct:
            try:
                data = response.json()
                params["json"] = self._extract_json_keys(data)
            except Exception:
                pass

        # Look for hidden params in JS
        js_params = re.findall(r'["\'](\w+)["\']:\s*(?:null|true|false|\d+|["\'])', response.text)
        for p in js_params:
            if len(p) > 1 and p not in params["get"] and p not in params["post"]:
                params["post"].append(p)

        return params

    def _extract_json_keys(self, data, prefix="") -> List[str]:
        """Recursively extract keys from JSON."""
        keys = []
        if isinstance(data, dict):
            for k, v in data.items():
                full_key = f"{prefix}.{k}" if prefix else k
                keys.append(full_key)
                keys.extend(self._extract_json_keys(v, full_key))
        elif isinstance(data, list) and data:
            keys.extend(self._extract_json_keys(data[0], prefix))
        return keys

    def fuzz_hidden_params(self, url: str, known_params: List[str]) -> List[str]:
        """Discover hidden parameters via brute-force."""
        found = []
        params = load_payloads(HIDDEN_PARAMS_PATH)
        if not params:
            params = ["id", "user", "token", "key", "debug", "admin", "page", "file", "path"]
        
        # Get baseline response
        baseline = make_request(self.session, "GET", url)
        if baseline is None:
            return found
        baseline_len = len(baseline.text)
        
        for param in params[:50]:
            if param in known_params:
                continue
            test_url = f"{url}{'&' if '?' in url else '?'}{param}=test_venom"
            resp = make_request(self.session, "GET", test_url)
            if resp and abs(len(resp.text) - baseline_len) > 50:
                found.append(param)
                log_info(f"Hidden param found: {param} at {url}")
        
        return found
