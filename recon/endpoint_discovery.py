"""Endpoint discovery module — crawls target for endpoints, forms, JS files."""
# For authorized security testing only.
import os
import urllib.parse
from typing import List, Dict
import requests
from core.utils import make_request, extract_forms, extract_links, load_payloads
from core.logger import log_info, log_warning

WORDLIST_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists", "directories.txt")
API_WORDLIST_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists", "api_endpoints.txt")


class EndpointDiscovery:
    def __init__(self, target, session: requests.Session):
        self.target = target
        self.session = session
        self.endpoints = []
        self.visited = set()
        self.max_crawl = 50

    def discover(self) -> List[Dict]:
        """Main discovery method combining crawl, directory brute-force, and form extraction."""
        self._crawl(self.target.url, depth=2)
        self._brute_directories()
        self._check_api_endpoints()
        
        # Always include the base URL
        if not any(e["url"] == self.target.url for e in self.endpoints):
            self.endpoints.append({"url": self.target.url, "method": "GET", "params": []})
        
        return self.endpoints

    def _crawl(self, url: str, depth: int = 2):
        """Crawl links up to given depth."""
        if depth == 0 or url in self.visited or len(self.visited) >= self.max_crawl:
            return
        self.visited.add(url)
        
        resp = make_request(self.session, "GET", url)
        if resp is None:
            return
        
        # Extract forms
        forms = extract_forms(resp.text, url)
        for form in forms:
            self.target.add_form(form)
            endpoint = {
                "url": form.get("action", url),
                "method": form.get("method", "post").upper(),
                "params": [inp["name"] for inp in form.get("inputs", [])],
            }
            if endpoint not in self.endpoints:
                self.endpoints.append(endpoint)
        
        # Extract GET params from URL
        parsed = urllib.parse.urlparse(url)
        if parsed.query:
            params = list(urllib.parse.parse_qs(parsed.query).keys())
            ep = {"url": url, "method": "GET", "params": params}
            if ep not in self.endpoints:
                self.endpoints.append(ep)
        
        # Crawl links
        links = extract_links(resp.text, self.target.base_url)
        for link in links:
            if self.target.base_url in link:
                self._crawl(link, depth - 1)

    def _brute_directories(self):
        """Brute-force common directories and files."""
        paths = load_payloads(WORDLIST_PATH)
        if not paths:
            paths = ["admin", "login", "api", "upload", "backup", ".git", "config", "test"]
        
        # Get baseline for 404 detection
        fake_resp = make_request(self.session, "GET", f"{self.target.base_url}/thispathshouldnotexist12345")
        baseline_status = fake_resp.status_code if fake_resp else 404
        
        for path in paths[:100]:
            url = f"{self.target.base_url}/{path.lstrip('/')}"
            if url in self.visited:
                continue
            resp = make_request(self.session, "GET", url)
            if resp and resp.status_code not in (404, baseline_status) and resp.status_code < 500:
                self.visited.add(url)
                ep = {"url": url, "method": "GET", "params": []}
                if ep not in self.endpoints:
                    self.endpoints.append(ep)
                    log_info(f"Found: {url} ({resp.status_code})")

    def _check_api_endpoints(self):
        """Check common API endpoints."""
        paths = load_payloads(API_WORDLIST_PATH)
        if not paths:
            paths = ["/api/v1/users", "/api/users", "/graphql", "/api/health", "/swagger.json"]
        
        for path in paths[:50]:
            url = f"{self.target.base_url}{path}"
            if url in self.visited:
                continue
            resp = make_request(self.session, "GET", url)
            if resp and resp.status_code not in (404,) and resp.status_code < 500:
                ep = {"url": url, "method": "GET", "params": []}
                if ep not in self.endpoints:
                    self.endpoints.append(ep)
