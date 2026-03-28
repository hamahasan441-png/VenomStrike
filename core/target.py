"""Target manager — URL normalization, availability check, endpoint management."""
# For authorized security testing only.
import requests
import urllib.parse
from typing import Optional, List, Dict
from core.logger import log_info, log_error, log_warning
from core.utils import normalize_url, make_request
from config import DEFAULT_TIMEOUT, DEFAULT_USER_AGENT
import urllib3
urllib3.disable_warnings()


class Target:
    def __init__(self, url: str, session: requests.Session = None):
        self.original_url = url
        self.url = normalize_url(url)
        self.base_url = self._get_base_url()
        self.session = session or self._create_session()
        self.endpoints = []
        self.forms = []
        self.parameters = {}
        self.available = False
        self.server_info = {}
        
    def _get_base_url(self) -> str:
        parsed = urllib.parse.urlparse(self.url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
        session.verify = False
        return session
    
    def check_availability(self) -> bool:
        """Check if target is available."""
        resp = make_request(self.session, "GET", self.url, timeout=DEFAULT_TIMEOUT)
        if resp is not None:
            self.available = True
            self._extract_server_info(resp)
            log_info(f"Target is available: {self.url} (Status: {resp.status_code})")
            return True
        log_error(f"Target is not available: {self.url}")
        return False
    
    def _extract_server_info(self, response: requests.Response):
        """Extract server information from response headers."""
        headers = response.headers
        self.server_info = {
            "server": headers.get("Server", "Unknown"),
            "x_powered_by": headers.get("X-Powered-By", ""),
            "content_type": headers.get("Content-Type", ""),
            "status_code": response.status_code,
        }
    
    def add_endpoint(self, url: str, method: str = "GET", params: List[str] = None):
        """Add a discovered endpoint."""
        endpoint = {
            "url": url,
            "method": method,
            "params": params or [],
        }
        if endpoint not in self.endpoints:
            self.endpoints.append(endpoint)
    
    def add_form(self, form: Dict):
        """Add a discovered form."""
        if form not in self.forms:
            self.forms.append(form)
    
    def get_attack_surface(self) -> List[Dict]:
        """Get complete attack surface."""
        surface = []
        for endpoint in self.endpoints:
            surface.append(endpoint)
        for form in self.forms:
            surface.append({
                "url": form.get("action", self.url),
                "method": form.get("method", "POST"),
                "params": [inp["name"] for inp in form.get("inputs", [])],
                "form": form,
            })
        return surface
    
    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "base_url": self.base_url,
            "available": self.available,
            "server_info": self.server_info,
            "endpoint_count": len(self.endpoints),
            "form_count": len(self.forms),
        }
