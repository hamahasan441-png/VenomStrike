"""HTTP session manager — cookies, headers, auth, proxy, user-agent rotation."""
# For authorized security testing only.
import requests
import random
from typing import Optional, Dict, List
from config import DEFAULT_USER_AGENT, DEFAULT_TIMEOUT
import urllib3
urllib3.disable_warnings()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (compatible; VenomStrike/1.0; Security Testing)",
]


class SessionManager:
    def __init__(
        self,
        cookie: str = "",
        headers: Dict = None,
        proxy: str = "",
        auth_user: str = "",
        auth_pass: str = "",
        rotate_ua: bool = False,
    ):
        self.cookie = cookie
        self.extra_headers = headers or {}
        self.proxy = proxy
        self.auth_user = auth_user
        self.auth_pass = auth_pass
        self.rotate_ua = rotate_ua
        self.session = self._build_session()
    
    def _build_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = False
        ua = random.choice(USER_AGENTS) if self.rotate_ua else DEFAULT_USER_AGENT
        session.headers.update({"User-Agent": ua})
        if self.cookie:
            for pair in self.cookie.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    name, _, value = pair.partition("=")
                    session.cookies.set(name.strip(), value.strip())
        if self.extra_headers:
            session.headers.update(self.extra_headers)
        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}
        if self.auth_user and self.auth_pass:
            session.auth = (self.auth_user, self.auth_pass)
        return session
    
    def get_session(self) -> requests.Session:
        return self.session
    
    def rotate_user_agent(self):
        ua = random.choice(USER_AGENTS)
        self.session.headers.update({"User-Agent": ua})
    
    def add_header(self, name: str, value: str):
        self.session.headers[name] = value
    
    def add_cookie(self, name: str, value: str):
        self.session.cookies.set(name, value)
