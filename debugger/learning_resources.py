"""Learning resources for each vulnerability type."""
# For authorized security testing only.
from typing import Dict, List


LEARNING_RESOURCES = {
    "SQL Injection": {
        "labs": [
            {"name": "PortSwigger SQL Injection Labs", "url": "https://portswigger.net/web-security/sql-injection"},
            {"name": "DVWA SQL Injection", "url": "https://github.com/digininja/DVWA"},
            {"name": "SQLi-labs", "url": "https://github.com/Audi-1/sqli-labs"},
        ],
        "reading": [
            {"name": "OWASP SQL Injection", "url": "https://owasp.org/www-community/attacks/SQL_Injection"},
            {"name": "SQL Injection Prevention Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"},
        ],
        "tools": ["sqlmap", "HackBar", "SQLi Dumper"],
        "difficulty": "Intermediate",
    },
    "XSS": {
        "labs": [
            {"name": "PortSwigger XSS Labs", "url": "https://portswigger.net/web-security/cross-site-scripting"},
            {"name": "XSS Game", "url": "https://xss-game.appspot.com/"},
            {"name": "Alert(1) to Win", "url": "https://alf.nu/alert1"},
        ],
        "reading": [
            {"name": "OWASP XSS", "url": "https://owasp.org/www-community/attacks/xss/"},
            {"name": "XSS Prevention Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"},
        ],
        "tools": ["XSSer", "DOMPurify tester", "XSStrike"],
        "difficulty": "Beginner-Intermediate",
    },
    "SSRF": {
        "labs": [
            {"name": "PortSwigger SSRF Labs", "url": "https://portswigger.net/web-security/ssrf"},
            {"name": "SSRF Vulnerable Lab", "url": "https://github.com/incredibleindishell/SSRF_Vulnerable_Lab"},
        ],
        "reading": [
            {"name": "OWASP SSRF", "url": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"},
            {"name": "HackTricks SSRF", "url": "https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery"},
        ],
        "tools": ["SSRFmap", "Burp Collaborator"],
        "difficulty": "Intermediate",
    },
    "JWT": {
        "labs": [
            {"name": "PortSwigger JWT Labs", "url": "https://portswigger.net/web-security/jwt"},
            {"name": "JWT Security Challenges", "url": "https://github.com/PortSwigger/jwt-authentication"},
        ],
        "reading": [
            {"name": "JWT Security Best Practices", "url": "https://curity.io/resources/learn/jwt-best-practices/"},
            {"name": "JWT Attack Playbook", "url": "https://github.com/ticarpi/jwt_tool/wiki"},
        ],
        "tools": ["jwt_tool", "jwt.io", "hashcat JWT mode"],
        "difficulty": "Intermediate-Advanced",
    },
    "CSRF": {
        "labs": [
            {"name": "PortSwigger CSRF Labs", "url": "https://portswigger.net/web-security/csrf"},
        ],
        "reading": [
            {"name": "OWASP CSRF", "url": "https://owasp.org/www-community/attacks/csrf"},
            {"name": "CSRF Prevention Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"},
        ],
        "tools": ["Burp Suite CSRF PoC generator"],
        "difficulty": "Beginner",
    },
    "LFI": {
        "labs": [
            {"name": "PortSwigger File Path Traversal Labs", "url": "https://portswigger.net/web-security/file-path-traversal"},
            {"name": "DVWA File Inclusion", "url": "https://github.com/digininja/DVWA"},
        ],
        "reading": [
            {"name": "OWASP Path Traversal", "url": "https://owasp.org/www-community/attacks/Path_Traversal"},
        ],
        "tools": ["dotdotpwn", "fimap"],
        "difficulty": "Beginner-Intermediate",
    },
}


class LearningResources:
    def get_resources(self, vuln_type: str) -> Dict:
        normalized = self._normalize(vuln_type)
        resources = LEARNING_RESOURCES.get(normalized, {
            "labs": [{"name": "HackTheBox", "url": "https://www.hackthebox.com"},
                     {"name": "TryHackMe", "url": "https://tryhackme.com"}],
            "reading": [{"name": "OWASP Top 10", "url": "https://owasp.org/www-project-top-ten/"}],
            "tools": ["Burp Suite", "OWASP ZAP"],
            "difficulty": "Varies",
        })
        return resources
    
    def _normalize(self, vuln_type: str) -> str:
        lower = vuln_type.lower()
        if "sql" in lower:
            return "SQL Injection"
        if "xss" in lower:
            return "XSS"
        if "ssrf" in lower:
            return "SSRF"
        if "jwt" in lower:
            return "JWT"
        if "csrf" in lower:
            return "CSRF"
        if "lfi" in lower or "path traversal" in lower:
            return "LFI"
        return vuln_type
    
    def get_all_resources(self) -> Dict:
        return LEARNING_RESOURCES
