"""Prevention guide — security best practices per vulnerability type."""
# For authorized security testing only.
from typing import Dict, List


PREVENTION_GUIDES = {
    "SQL Injection": {
        "title": "SQL Injection Prevention",
        "short": "Use parameterized queries and stored procedures. Never concatenate user input into SQL.",
        "practices": [
            "Use parameterized queries or prepared statements",
            "Use an ORM (SQLAlchemy, Hibernate, Entity Framework)",
            "Apply principle of least privilege to DB accounts",
            "Sanitize and validate all input",
            "Implement WAF rules for SQL injection patterns",
            "Enable database query logging and alerting",
        ],
        "headers": [],
        "tools": ["SQLMap (testing)", "HaveIBeenPwned (data breach checks)"],
    },
    "XSS": {
        "title": "XSS Prevention",
        "short": "Encode all output, implement Content-Security-Policy, use XSS-safe templating.",
        "practices": [
            "HTML-encode all user-supplied output",
            "Implement strict Content-Security-Policy header",
            "Use X-XSS-Protection header (legacy browsers)",
            "Use HttpOnly and Secure flags on session cookies",
            "Validate and sanitize rich text with allowlists (DOMPurify)",
            "Avoid dangerous functions: innerHTML, document.write, eval",
        ],
        "headers": [
            "Content-Security-Policy: default-src 'self'; script-src 'self'",
            "X-XSS-Protection: 1; mode=block",
            "X-Content-Type-Options: nosniff",
        ],
        "tools": ["DOMPurify", "CSP Evaluator", "retire.js"],
    },
    "CSRF": {
        "title": "CSRF Prevention",
        "short": "Use CSRF tokens, SameSite cookies, and verify Origin/Referer headers.",
        "practices": [
            "Implement synchronizer token pattern (CSRF tokens)",
            "Use SameSite=Strict or SameSite=Lax cookie attribute",
            "Verify Origin and Referer headers for state-changing requests",
            "Use Double Submit Cookie pattern as backup",
            "Implement custom request headers (X-Requested-With) for AJAX",
        ],
        "headers": [
            "Set-Cookie: session=xxx; SameSite=Strict; Secure; HttpOnly",
        ],
        "tools": ["Django CSRF middleware", "Flask-WTF", "Spring Security CSRF"],
    },
    "SSRF": {
        "title": "SSRF Prevention",
        "short": "Validate and allowlist URLs. Block access to internal IP ranges.",
        "practices": [
            "Maintain an allowlist of permitted hosts/domains",
            "Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x)",
            "Use DNS pinning to prevent DNS rebinding",
            "Disable unnecessary URL scheme handlers (file://, dict://, gopher://)",
            "Run HTTP fetch services in isolated network segments",
            "Log and monitor all outbound HTTP requests",
        ],
        "headers": [],
        "tools": ["ssrfmap", "gopherus", "cloud metadata service protection"],
    },
    "LFI": {
        "title": "LFI Prevention",
        "short": "Never use user input in file paths. Use allowlists for file access.",
        "practices": [
            "Never use user-controlled input in file system operations",
            "Use an allowlist of permitted filenames/paths",
            "Resolve canonical paths and verify they stay within base directory",
            "Disable PHP functions: allow_url_include, allow_url_fopen",
            "Run application with minimal filesystem permissions",
        ],
        "headers": [],
        "tools": ["open_basedir restriction (PHP)", "chroot/jail"],
    },
    "Command Injection": {
        "title": "Command Injection Prevention",
        "short": "Never pass user input to OS commands. Use APIs instead of shell commands.",
        "practices": [
            "Never use user input in OS command execution",
            "Use language-native APIs instead of shell commands (e.g., Python's socket module instead of ping)",
            "If shell is necessary, use list arguments (subprocess with list, not shell=True)",
            "Allowlist input: only permit alphanumeric characters and specific symbols",
            "Apply principle of least privilege to application OS user",
        ],
        "headers": [],
        "tools": ["Semgrep rules for command injection", "Bandit (Python)"],
    },
    "JWT": {
        "title": "JWT Security",
        "short": "Use strong secrets, explicit algorithm validation, and verify all claims.",
        "practices": [
            "Use a cryptographically random secret of at least 256 bits",
            "Explicitly specify allowed algorithms (never accept 'none' or 'alg' from token)",
            "Validate all claims: exp, iat, iss, aud, sub",
            "Use asymmetric algorithms (RS256) for high-security scenarios",
            "Implement token revocation (blocklist for logout)",
            "Keep token lifetimes short (15-30 minutes for access tokens)",
        ],
        "headers": [],
        "tools": ["jwt.io debugger", "OWASP JWT Security Cheat Sheet"],
    },
    "XXE": {
        "title": "XXE Prevention",
        "short": "Disable external entity processing in XML parsers.",
        "practices": [
            "Use defusedxml or equivalent safe XML parsing libraries",
            "Disable DOCTYPE declarations where not needed",
            "Disable external entity resolution",
            "Use JSON instead of XML where possible",
            "Apply XML schema validation on trusted schemas",
        ],
        "headers": [],
        "tools": ["defusedxml (Python)", "OWASP XXE Prevention Cheat Sheet"],
    },
}


class PreventionGuide:
    def get_guide(self, finding: Dict) -> Dict:
        """Get prevention guide for a finding."""
        vuln_type = finding.get("vuln_type", "")
        normalized = self._normalize(vuln_type)
        
        guide = PREVENTION_GUIDES.get(normalized, {
            "title": f"{vuln_type} Prevention",
            "short": "Follow OWASP secure coding guidelines for this vulnerability type.",
            "practices": [
                "Validate and sanitize all user input",
                "Apply principle of least privilege",
                "Implement defense in depth",
                "Keep dependencies updated",
                "Perform regular security testing",
            ],
            "headers": [],
            "tools": ["OWASP ZAP", "Burp Suite"],
        })
        
        return guide
    
    def _normalize(self, vuln_type: str) -> str:
        lower = vuln_type.lower()
        if "sql" in lower:
            return "SQL Injection"
        if "xss" in lower:
            return "XSS"
        if "csrf" in lower:
            return "CSRF"
        if "ssrf" in lower:
            return "SSRF"
        if "lfi" in lower or "path traversal" in lower:
            return "LFI"
        if "command" in lower or "cmd" in lower:
            return "Command Injection"
        if "jwt" in lower:
            return "JWT"
        if "xxe" in lower:
            return "XXE"
        return vuln_type
