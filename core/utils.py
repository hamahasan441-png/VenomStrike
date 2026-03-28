"""HTTP request wrapper, URL parser, payload encoder, helpers."""
# For authorized security testing only.
import urllib.parse
import re
import time
import hashlib
import requests
from typing import Optional, Dict, List, Any
from config import DEFAULT_TIMEOUT, DEFAULT_USER_AGENT


def make_request(
    session: requests.Session,
    method: str,
    url: str,
    params=None,
    data=None,
    json=None,
    headers=None,
    timeout=DEFAULT_TIMEOUT,
    allow_redirects=True,
) -> Optional[requests.Response]:
    """Safe HTTP request wrapper with error handling."""
    try:
        resp = session.request(
            method=method.upper(),
            url=url,
            params=params,
            data=data,
            json=json,
            headers=headers or {},
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=False,
        )
        return resp
    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.ConnectionError:
        return None
    except Exception:
        return None


def normalize_url(url: str) -> str:
    """Normalize a URL by ensuring it has a scheme."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urllib.parse.urlparse(url)
    return parsed.geturl()


def get_base_url(url: str) -> str:
    """Get base URL (scheme + netloc)."""
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def encode_payload(payload: str, encoding: str = "url") -> str:
    """Encode payload in various ways."""
    if encoding == "url":
        return urllib.parse.quote(payload)
    elif encoding == "double_url":
        return urllib.parse.quote(urllib.parse.quote(payload))
    elif encoding == "html":
        return payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    elif encoding == "base64":
        import base64
        return base64.b64encode(payload.encode()).decode()
    return payload


def response_hash(response: requests.Response) -> str:
    """Create a hash of the response for comparison."""
    if response is None:
        return ""
    content = f"{response.status_code}{len(response.content)}{response.text[:500]}"
    return hashlib.md5(content.encode()).hexdigest()


def response_diff(resp1: requests.Response, resp2: requests.Response) -> float:
    """Calculate difference percentage between two responses."""
    if resp1 is None or resp2 is None:
        return 0.0
    len1 = len(resp1.text)
    len2 = len(resp2.text)
    if len1 == 0 and len2 == 0:
        return 0.0
    diff = abs(len1 - len2) / max(len1, len2, 1)
    return diff * 100


def extract_forms(html: str, base_url: str) -> List[Dict]:
    """Extract all forms from HTML."""
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        if action and not action.startswith("http"):
            action = urllib.parse.urljoin(base_url, action)
        elif not action:
            action = base_url
        method = form.get("method", "get").lower()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            inp_name = inp.get("name", "")
            inp_type = inp.get("type", "text")
            inp_value = inp.get("value", "")
            if inp_name:
                inputs.append({"name": inp_name, "type": inp_type, "value": inp_value})
        forms.append({"action": action, "method": method, "inputs": inputs})
    return forms


def extract_links(html: str, base_url: str) -> List[str]:
    """Extract all links from HTML."""
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for tag in soup.find_all("a", href=True):
        href = tag["href"]
        if href.startswith("http"):
            links.add(href)
        elif href.startswith("/"):
            links.add(urllib.parse.urljoin(base_url, href))
    return list(links)


def load_payloads(filepath: str) -> List[str]:
    """Load payloads from a text file."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return lines
    except FileNotFoundError:
        return []


def timing_test(func, *args, threshold=2.0, **kwargs) -> tuple:
    """Test if a function takes significantly longer with payload (timing attack detection)."""
    start = time.time()
    result = func(*args, **kwargs)
    elapsed = time.time() - start
    return result, elapsed, elapsed >= threshold


def is_valid_url(url: str) -> bool:
    """Check if a URL is valid."""
    try:
        parsed = urllib.parse.urlparse(url)
        return all([parsed.scheme in ("http", "https"), parsed.netloc])
    except Exception:
        return False


def sanitize_param(param: str) -> str:
    """Remove dangerous characters from parameter names."""
    return re.sub(r"[^\w\-\.]", "", param)


def build_finding(
    vuln_type: str,
    url: str,
    param: str,
    payload: str,
    severity: str,
    confidence: int,
    evidence: Dict,
    cwe: str = "",
    cvss: float = 0.0,
    owasp: str = "",
) -> Dict:
    """Build a standardized finding dictionary."""
    return {
        "vuln_type": vuln_type,
        "url": url,
        "param": param,
        "payload": payload,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
        "cwe": cwe,
        "cvss": cvss,
        "owasp": owasp,
        "timestamp": time.time(),
    }
