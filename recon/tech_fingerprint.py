"""Technology fingerprinting — detect frameworks, CMS, server, WAF."""
# For authorized security testing only.
import re
from typing import Dict, List
import requests
from core.utils import make_request
from core.logger import log_info


class TechFingerprint:
    def __init__(self, session: requests.Session):
        self.session = session

    def fingerprint(self, target_url: str, response: requests.Response = None) -> Dict:
        """Run full fingerprinting and return tech stack info."""
        if response is None:
            response = make_request(self.session, "GET", target_url)
        
        result = {
            "server": self._detect_server(response),
            "language": self._detect_language(response),
            "framework": self._detect_framework(response),
            "cms": self._detect_cms(response),
            "waf": self._detect_waf(response),
            "database": self._detect_database(response),
            "headers": dict(response.headers) if response else {},
        }
        log_info(f"Tech stack: {result}")
        return result

    def _detect_server(self, response: requests.Response) -> str:
        if response is None:
            return "Unknown"
        server = response.headers.get("Server", "")
        x_powered = response.headers.get("X-Powered-By", "")
        if server:
            return server
        if x_powered:
            return x_powered
        return "Unknown"

    def _detect_language(self, response: requests.Response) -> str:
        if response is None:
            return "Unknown"
        x_powered = response.headers.get("X-Powered-By", "")
        patterns = {
            "PHP": [r"PHP/[\d\.]+", r"\.php", r"PHPSESSID"],
            "ASP.NET": [r"ASP\.NET", r"\.aspx", r"__VIEWSTATE"],
            "Java": [r"JSESSIONID", r"\.jsp", r"Java/"],
            "Python": [r"Python/", r"Django", r"Flask", r"Werkzeug"],
            "Ruby": [r"Ruby/", r"Rails", r"rack"],
            "Node.js": [r"Express", r"node\.js", r"Node\.js"],
            "Go": [r"Go-http-client", r"go/"],
        }
        text = f"{x_powered} {response.text[:2000]} {str(response.headers)}"
        for lang, pats in patterns.items():
            for pat in pats:
                if re.search(pat, text, re.IGNORECASE):
                    return lang
        return "Unknown"

    def _detect_framework(self, response: requests.Response) -> str:
        if response is None:
            return "Unknown"
        text = response.text[:3000]
        frameworks = {
            "Django": ["csrfmiddlewaretoken", "django", "__admin_media_prefix__"],
            "Laravel": ["laravel_session", "XSRF-TOKEN", "Laravel"],
            "Spring": ["JSESSIONID", "spring", "springframework"],
            "Express.js": ["X-Powered-By: Express", "express"],
            "Ruby on Rails": ["_rails", "authenticity_token"],
            "ASP.NET MVC": ["__RequestVerificationToken", "asp.net"],
            "Angular": ["ng-version", "ng-app", "_ng"],
            "React": ["__REACT_DEVTOOLS", "react-dom"],
            "Vue.js": ["__vue__", "v-bind", "v-model"],
            "WordPress": ["wp-content", "wp-login", "wordpress"],
        }
        combined = f"{text} {str(response.headers)}"
        for fw, indicators in frameworks.items():
            for indicator in indicators:
                if indicator.lower() in combined.lower():
                    return fw
        return "Unknown"

    def _detect_cms(self, response: requests.Response) -> str:
        if response is None:
            return "Unknown"
        text = response.text[:3000]
        cms_patterns = {
            "WordPress": ["wp-content", "wp-includes", "wordpress"],
            "Joomla": ["joomla", "/components/com_", "Joomla!"],
            "Drupal": ["drupal", "Drupal.settings", "/sites/default/"],
            "Magento": ["Magento", "mage/", "varien"],
            "Shopify": ["shopify", "myshopify.com", "cdn.shopify"],
        }
        for cms, patterns in cms_patterns.items():
            for pat in patterns:
                if pat.lower() in text.lower():
                    return cms
        return "Unknown"

    def _detect_waf(self, response: requests.Response) -> str:
        if response is None:
            return "Unknown"
        waf_headers = {
            "Cloudflare": ["cf-ray", "cloudflare"],
            "ModSecurity": ["mod_security", "NOYB"],
            "AWS WAF": ["x-amzn-requestid", "awswaf"],
            "Imperva": ["x-iinfo", "incap_ses"],
            "F5 BIG-IP ASM": ["TS", "BigIP"],
            "Akamai": ["akamai", "aka-"],
        }
        header_str = str(response.headers).lower()
        for waf, patterns in waf_headers.items():
            for pat in patterns:
                if pat.lower() in header_str:
                    return waf
        return "None detected"

    def _detect_database(self, response: requests.Response) -> str:
        """Detect the likely database backend from response indicators."""
        if response is None:
            return "Unknown"
        text = f"{response.text[:3000]} {str(response.headers)}"
        db_patterns = {
            "MySQL": [r"mysql", r"MariaDB", r"MYSQL_", r"mysqli"],
            "PostgreSQL": [r"postgresql", r"pg_", r"pgsql", r"Npgsql"],
            "MSSQL": [r"sql\s*server", r"mssql", r"sqlsrv", r"System\.Data\.SqlClient"],
            "SQLite": [r"sqlite", r"SQLITE_"],
            "Oracle": [r"oracle", r"ORA-\d{4,5}"],
            "MongoDB": [r"mongodb", r"mongoose", r"MongoError"],
            "Redis": [r"redis", r"WRONGTYPE"],
        }
        for db, patterns in db_patterns.items():
            for pat in patterns:
                if re.search(pat, text, re.IGNORECASE):
                    return db
        return "Unknown"
