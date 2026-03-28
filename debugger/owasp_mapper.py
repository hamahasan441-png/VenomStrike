"""OWASP/CWE/CVSS mapping for vulnerability types."""
# For authorized security testing only.
from typing import Dict, List


OWASP_MAPPING = {
    "SQL Injection": {
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-89",
        "cvss_base": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "wasc": "WASC-19",
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    },
    "XSS": {
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-79",
        "cvss_base": 6.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "wasc": "WASC-8",
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    },
    "SSRF": {
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "cwe": "CWE-918",
        "cvss_base": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "wasc": "WASC-40",
        "references": [
            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
    },
    "CSRF": {
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-352",
        "cvss_base": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        "wasc": "WASC-9",
        "references": [
            "https://owasp.org/www-community/attacks/csrf",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
    },
    "LFI": {
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-22",
        "cvss_base": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "wasc": "WASC-33",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
            "https://cwe.mitre.org/data/definitions/22.html",
        ],
    },
    "Command Injection": {
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-78",
        "cvss_base": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "wasc": "WASC-31",
        "references": [
            "https://owasp.org/www-community/attacks/Command_Injection",
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
    },
    "IDOR": {
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-639",
        "cvss_base": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "wasc": "WASC-2",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
            "https://cwe.mitre.org/data/definitions/639.html",
        ],
    },
    "XXE": {
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-611",
        "cvss_base": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "wasc": "WASC-43",
        "references": [
            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
        ],
    },
    "JWT": {
        "owasp": "A02:2021 - Cryptographic Failures",
        "cwe": "CWE-347",
        "cvss_base": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "wasc": "WASC-37",
        "references": [
            "https://jwt.io/introduction",
            "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
        ],
    },
    "Clickjacking": {
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-1021",
        "cvss_base": 4.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "wasc": "WASC-12",
        "references": [
            "https://owasp.org/www-community/attacks/Clickjacking",
            "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
        ],
    },
}


class OWASPMapper:
    def get_owasp_info(self, finding: Dict) -> Dict:
        vuln_type = finding.get("vuln_type", "")
        normalized = self._normalize(vuln_type)
        return OWASP_MAPPING.get(normalized, {
            "owasp": "A04:2021 - Insecure Design",
            "cwe": finding.get("cwe", "CWE-1"),
            "cvss_base": finding.get("cvss", 5.0),
            "references": ["https://owasp.org/www-project-top-ten/"],
        })
    
    def get_references(self, vuln_type: str) -> List[str]:
        normalized = self._normalize(vuln_type)
        info = OWASP_MAPPING.get(normalized, {})
        return info.get("references", ["https://owasp.org/www-project-top-ten/"])
    
    def _normalize(self, vuln_type: str) -> str:
        lower = vuln_type.lower()
        if "sql" in lower:
            return "SQL Injection"
        if "xss" in lower or "cross-site scripting" in lower:
            return "XSS"
        if "ssrf" in lower:
            return "SSRF"
        if "csrf" in lower:
            return "CSRF"
        if "lfi" in lower or "path traversal" in lower:
            return "LFI"
        if "command" in lower or "cmd" in lower:
            return "Command Injection"
        if "idor" in lower:
            return "IDOR"
        if "xxe" in lower:
            return "XXE"
        if "jwt" in lower:
            return "JWT"
        if "clickjack" in lower:
            return "Clickjacking"
        return vuln_type
