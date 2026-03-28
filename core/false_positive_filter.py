"""False positive detection per vulnerability type."""
# For authorized security testing only.
import re
from typing import Optional
import requests


class FalsePositiveFilter:
    
    def check_sqli(self, baseline_resp: requests.Response, payload_resp: requests.Response, 
                   payload: str) -> bool:
        """Verify SQLi is real: error only appears WITH payload."""
        if payload_resp is None:
            return False
        sql_errors = [
            r"sql syntax", r"mysql_fetch", r"ORA-\d+", r"PostgreSQL.*ERROR",
            r"Warning.*mysql", r"SQLite.*error", r"Microsoft.*ODBC",
            r"Unclosed quotation mark", r"quoted string not properly terminated",
            r"syntax error.*SQL", r"SQLSTATE\[", r"DB Error",
        ]
        for pattern in sql_errors:
            if re.search(pattern, payload_resp.text, re.IGNORECASE):
                if not baseline_resp or not re.search(pattern, baseline_resp.text, re.IGNORECASE):
                    return True
        return False
    
    def check_xss(self, response: requests.Response, payload: str) -> bool:
        """Verify XSS: payload is reflected UNESCAPED."""
        if response is None:
            return False
        dangerous_parts = ["<script", "onerror=", "onload=", "alert(", "prompt(", "confirm("]
        for part in dangerous_parts:
            if part.lower() in payload.lower() and part.lower() in response.text.lower():
                if "&lt;" not in response.text and "&gt;" not in response.text:
                    return True
                if part in response.text:
                    return True
        return False
    
    def check_lfi(self, response: requests.Response) -> bool:
        """Verify LFI: actual file content is returned."""
        if response is None:
            return False
        lfi_indicators = [
            r"root:.*:0:0:", r"\[boot loader\]", r"\[operating systems\]",
            r"# /etc/hosts", r"localhost.*127\.0\.0\.1",
            r"# This file", r"bin/bash", r"sbin/nologin",
        ]
        for pattern in lfi_indicators:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True
        return False
    
    def check_ssrf(self, baseline_resp: requests.Response, payload_resp: requests.Response) -> bool:
        """Verify SSRF: different response vs normal."""
        if payload_resp is None:
            return False
        if baseline_resp is None:
            return True
        if abs(len(payload_resp.text) - len(baseline_resp.text)) > 50:
            return True
        if payload_resp.status_code != baseline_resp.status_code:
            return True
        return False
    
    def check_cmd_injection(self, response: requests.Response, baseline_resp: requests.Response,
                            timing: float = 0) -> bool:
        """Verify command injection via output or timing."""
        if response is None:
            return False
        cmd_outputs = [
            r"uid=\d+", r"root@", r"volume in drive", r"directory of",
            r"total \d+", r"drwxr", r"\$ ", r"# ",
        ]
        for pattern in cmd_outputs:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True
        if timing >= 4.0:
            return True
        return False
    
    def check_ssti(self, response: requests.Response, expected_output: str) -> bool:
        """Verify SSTI: check if template expression was evaluated."""
        if response is None:
            return False
        return expected_output in response.text
    
    def check_dir(self, response: requests.Response, baseline_hash: str) -> bool:
        """Verify directory finding is real, not a soft 404."""
        if response is None or response.status_code in (404, 403, 400, 500):
            return False
        import hashlib
        current_hash = hashlib.md5(f"{response.status_code}{len(response.content)}".encode()).hexdigest()
        return current_hash != baseline_hash and response.status_code == 200
