"""Context-aware false positive detection per vulnerability type."""
# For authorized security testing only.
import re
from typing import Optional, Dict
import requests


class FalsePositiveFilter:
    """Enhanced false positive filter with baseline awareness.

    Every check method now:
    1. Requires a baseline response (normal request without payload)
    2. Verifies the indicator is ONLY present with the payload
    3. Returns a dict with is_real (bool) and reason (str) for audit trail
    """

    # ── SQL Injection ──────────────────────────────────────────────

    SQL_ERRORS = [
        r"you have an error in your sql syntax",
        r"warning.*mysql",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"sqlstate\[",
        r"ora-\d{4,5}",
        r"microsoft.*odbc.*sql server",
        r"sqlite.*error",
        r"postgresql.*error",
        r"pg_query\(\).*failed",
        r"db error",
        r"mysql_fetch",
        r"sql syntax.*mariadb",
        r"division by zero",
        r"supplied argument is not a valid mysql",
    ]

    def check_sqli(self, baseline_resp: requests.Response,
                   payload_resp: requests.Response, payload: str) -> bool:
        """Verify SQLi is real: SQL error only appears WITH payload."""
        if payload_resp is None:
            return False
        for pattern in self.SQL_ERRORS:
            if re.search(pattern, payload_resp.text, re.IGNORECASE):
                if not baseline_resp or not re.search(pattern, baseline_resp.text, re.IGNORECASE):
                    return True
        return False

    def check_sqli_detailed(self, baseline_resp: requests.Response,
                            payload_resp: requests.Response,
                            payload: str) -> Dict:
        """Enhanced SQLi check returning structured proof."""
        result = {"is_real": False, "reason": "", "matched_pattern": "", "proof_data": {}}
        if payload_resp is None:
            result["reason"] = "No response received"
            return result

        for pattern in self.SQL_ERRORS:
            match = re.search(pattern, payload_resp.text, re.IGNORECASE)
            if match:
                baseline_has = baseline_resp and re.search(pattern, baseline_resp.text, re.IGNORECASE)
                if not baseline_has:
                    result["is_real"] = True
                    result["matched_pattern"] = pattern
                    result["reason"] = (
                        f"SQL error '{match.group()[:80]}' found in payload response "
                        f"but NOT in baseline response"
                    )
                    result["proof_data"] = {
                        "error_pattern": pattern,
                        "error_match": match.group()[:100],
                        "baseline_missing_pattern": True,
                        "baseline_status": baseline_resp.status_code if baseline_resp else None,
                        "payload_status": payload_resp.status_code,
                    }
                    return result
                else:
                    result["reason"] = f"Pattern '{pattern}' also appears in baseline — likely normal"
        result["reason"] = "No SQL error patterns detected in payload response"
        return result

    # ── XSS ────────────────────────────────────────────────────────

    XSS_DANGEROUS_PARTS = [
        "<script", "onerror=", "onload=", "alert(", "prompt(", "confirm(",
        "<svg", "<img", "onfocus=", "onmouseover=", "ontoggle=",
        "javascript:", "<body", "<iframe",
    ]

    def check_xss(self, response: requests.Response, payload: str) -> bool:
        """Verify XSS: payload is reflected UNESCAPED."""
        if response is None:
            return False
        for part in self.XSS_DANGEROUS_PARTS:
            if part.lower() in payload.lower() and part.lower() in response.text.lower():
                if "&lt;" not in response.text and "&gt;" not in response.text:
                    return True
                if part in response.text:
                    return True
        return False

    def check_xss_detailed(self, baseline_resp: requests.Response,
                           payload_resp: requests.Response,
                           payload: str) -> Dict:
        """Enhanced XSS check with baseline comparison and encoding detection."""
        result = {"is_real": False, "reason": "", "reflected_part": "", "proof_data": {}}
        if payload_resp is None:
            result["reason"] = "No response received"
            return result

        resp_text = payload_resp.text
        resp_lower = resp_text.lower()

        for part in self.XSS_DANGEROUS_PARTS:
            if part.lower() not in payload.lower():
                continue
            if part.lower() not in resp_lower:
                continue

            # Check if the part is HTML-entity-encoded (escaped)
            escaped_versions = [
                part.replace("<", "&lt;").replace(">", "&gt;"),
                part.replace("<", "&#60;").replace(">", "&#62;"),
                part.replace("<", "&#x3c;").replace(">", "&#x3e;"),
            ]
            is_escaped = any(esc.lower() in resp_lower for esc in escaped_versions)

            # Also check baseline — if dangerous part exists in baseline, it's not our injection
            baseline_has = baseline_resp and part.lower() in baseline_resp.text.lower()

            if not is_escaped and not baseline_has:
                result["is_real"] = True
                result["reflected_part"] = part
                result["reason"] = (
                    f"XSS payload part '{part}' reflected UNESCAPED in response "
                    f"and NOT present in baseline"
                )
                result["proof_data"] = {
                    "reflected_payload": True,
                    "reflected_part": part,
                    "baseline_missing_pattern": True,
                    "encoding_detected": False,
                }
                return result
            elif is_escaped:
                result["reason"] = f"Payload part '{part}' is HTML-entity-encoded — safe"
            elif baseline_has:
                result["reason"] = f"Payload part '{part}' also exists in baseline — not injected"

        if not result["reason"]:
            result["reason"] = "Payload not reflected unescaped in response"
        return result

    # ── LFI / Path Traversal ───────────────────────────────────────

    LFI_INDICATORS = [
        (r"root:.*:0:0:", "Unix /etc/passwd root entry"),
        (r"\[boot loader\]", "Windows boot.ini content"),
        (r"\[operating systems\]", "Windows boot.ini content"),
        (r"localhost.*127\.0\.0\.1", "/etc/hosts localhost entry"),
        (r"bin/(ba)?sh", "Unix shell path reference"),
        (r"sbin/nologin", "Unix nologin shell"),
        (r"daemon:.*:/usr/sbin", "Unix daemon account"),
        (r"www-data:.*:/var/www", "Unix web server account"),
    ]

    def check_lfi(self, response: requests.Response) -> bool:
        """Verify LFI: actual file content is returned."""
        if response is None:
            return False
        for pattern, _ in self.LFI_INDICATORS:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True
        return False

    def check_lfi_detailed(self, baseline_resp: requests.Response,
                           payload_resp: requests.Response) -> Dict:
        """Enhanced LFI check with baseline comparison."""
        result = {"is_real": False, "reason": "", "indicator": "", "proof_data": {}}
        if payload_resp is None:
            result["reason"] = "No response received"
            return result

        for pattern, description in self.LFI_INDICATORS:
            match = re.search(pattern, payload_resp.text, re.IGNORECASE)
            if match:
                baseline_has = baseline_resp and re.search(pattern, baseline_resp.text, re.IGNORECASE)
                if not baseline_has:
                    result["is_real"] = True
                    result["indicator"] = description
                    result["reason"] = (
                        f"File content indicator '{description}' ({match.group()[:60]}) "
                        f"found in payload response but NOT in baseline"
                    )
                    result["proof_data"] = {
                        "file_content_indicator": description,
                        "matched_text": match.group()[:100],
                        "baseline_missing_pattern": True,
                    }
                    return result
                else:
                    result["reason"] = f"Pattern '{description}' also in baseline — may be normal content"

        result["reason"] = "No file content indicators found in response"
        return result

    # ── SSRF ───────────────────────────────────────────────────────

    CLOUD_METADATA_INDICATORS = [
        r"ami-id", r"instance-id", r"instance-type",
        r"security-credentials", r"iam/info",
        r"computeMetadata", r"metadata\.google",
        r"latest/meta-data",
    ]

    def check_ssrf(self, baseline_resp: requests.Response,
                   payload_resp: requests.Response) -> bool:
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

    def check_ssrf_detailed(self, baseline_resp: requests.Response,
                            payload_resp: requests.Response,
                            payload: str) -> Dict:
        """Enhanced SSRF check with content verification for cloud metadata."""
        result = {"is_real": False, "reason": "", "proof_data": {}}
        if payload_resp is None:
            result["reason"] = "No response received"
            return result

        is_cloud_payload = any(
            t in payload for t in ["169.254.169.254", "metadata.google", "100.100.100.200"]
        )

        # Check for cloud metadata content
        if is_cloud_payload:
            for pattern in self.CLOUD_METADATA_INDICATORS:
                match = re.search(pattern, payload_resp.text, re.IGNORECASE)
                if match:
                    result["is_real"] = True
                    result["reason"] = (
                        f"Cloud metadata indicator '{match.group()[:60]}' found in response, "
                        f"confirming SSRF to metadata service"
                    )
                    result["proof_data"] = {
                        "metadata_content": match.group()[:100],
                        "response_diff_percent": 100.0,
                        "baseline_length": len(baseline_resp.text) if baseline_resp else 0,
                        "payload_length": len(payload_resp.text),
                    }
                    return result

        # Fallback: response diff analysis
        if baseline_resp is None:
            result["is_real"] = True
            result["reason"] = "No baseline available for comparison, response received"
            return result

        len_diff = abs(len(payload_resp.text) - len(baseline_resp.text))
        status_diff = payload_resp.status_code != baseline_resp.status_code
        diff_percent = (len_diff / max(len(baseline_resp.text), 1)) * 100

        if len_diff > 100 or (status_diff and payload_resp.status_code == 200):
            result["is_real"] = True
            result["reason"] = (
                f"Response differs significantly: "
                f"{len_diff} bytes length diff ({diff_percent:.0f}%), "
                f"status {baseline_resp.status_code} -> {payload_resp.status_code}"
            )
            result["proof_data"] = {
                "response_diff_percent": diff_percent,
                "baseline_length": len(baseline_resp.text),
                "payload_length": len(payload_resp.text),
                "baseline_status": baseline_resp.status_code,
                "payload_status": payload_resp.status_code,
            }
            return result
        elif len_diff > 50:
            result["reason"] = f"Minor response diff ({len_diff} bytes) — marginal evidence"
        else:
            result["reason"] = f"Responses too similar (diff: {len_diff} bytes)"

        return result

    # ── Command Injection ──────────────────────────────────────────

    CMD_OUTPUTS = [
        (r"uid=\d+\(\w+\)", "Unix id command output"),
        (r"root:.*:0:0:", "Unix /etc/passwd content"),
        (r"Linux \S+ \d+\.\d+", "Unix uname output"),
        (r"Windows IP Configuration", "Windows ipconfig output"),
        (r"Directory of [A-Z]:\\", "Windows dir command output"),
        (r"volume in drive [A-Z]", "Windows dir header"),
        (r"drwxr[-x]", "Unix ls -la output"),
        (r"total \d+\s", "Unix ls total line"),
    ]

    def check_cmd_injection(self, response: requests.Response,
                            baseline_resp: requests.Response,
                            timing: float = 0) -> bool:
        """Verify command injection via output or timing."""
        if response is None:
            return False
        for pattern, _ in self.CMD_OUTPUTS:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True
        if timing >= 4.0:
            return True
        return False

    def check_cmd_detailed(self, baseline_resp: requests.Response,
                           payload_resp: requests.Response,
                           timing: float = 0,
                           baseline_timing: float = 0) -> Dict:
        """Enhanced command injection check with baseline comparison."""
        result = {"is_real": False, "reason": "", "proof_data": {}}
        if payload_resp is None:
            result["reason"] = "No response received"
            return result

        # Output-based detection
        for pattern, description in self.CMD_OUTPUTS:
            match = re.search(pattern, payload_resp.text, re.IGNORECASE)
            if match:
                baseline_has = baseline_resp and re.search(pattern, baseline_resp.text, re.IGNORECASE)
                if not baseline_has:
                    result["is_real"] = True
                    result["reason"] = (
                        f"Command output '{description}' ({match.group()[:60]}) "
                        f"found in payload response but NOT in baseline"
                    )
                    result["proof_data"] = {
                        "command_output": description,
                        "matched_text": match.group()[:100],
                        "baseline_missing_pattern": True,
                    }
                    return result
                else:
                    result["reason"] = f"Pattern '{description}' also in baseline — normal content"

        # Timing-based detection (with baseline calibration)
        if timing > 0:
            timing_delta = timing - baseline_timing
            if timing_delta >= 3.5:
                result["is_real"] = True
                result["reason"] = (
                    f"Timing anomaly: payload took {timing:.1f}s, "
                    f"baseline took {baseline_timing:.1f}s "
                    f"(delta: {timing_delta:.1f}s)"
                )
                result["proof_data"] = {
                    "timing_diff": timing,
                    "baseline_time": baseline_timing,
                }
                return result

        if not result["reason"]:
            result["reason"] = "No command output patterns or timing anomalies detected"
        return result

    # ── SSTI ───────────────────────────────────────────────────────

    def check_ssti(self, response: requests.Response, expected_output: str) -> bool:
        """Verify SSTI: check if template expression was evaluated."""
        if response is None:
            return False
        return expected_output in response.text

    def check_ssti_detailed(self, baseline_resp: requests.Response,
                            payload_resp: requests.Response,
                            expected_output: str) -> Dict:
        """Enhanced SSTI check — confirm expression result present only in payload response."""
        result = {"is_real": False, "reason": "", "proof_data": {}}
        if payload_resp is None:
            result["reason"] = "No response received"
            return result

        if expected_output in payload_resp.text:
            baseline_has = baseline_resp and expected_output in baseline_resp.text
            if not baseline_has:
                result["is_real"] = True
                result["reason"] = (
                    f"Template expression evaluated: '{expected_output}' "
                    f"found in payload response but NOT in baseline"
                )
                result["proof_data"] = {
                    "expected_output": expected_output,
                    "baseline_missing_pattern": True,
                }
            else:
                result["reason"] = f"'{expected_output}' also exists in baseline — not injected"
        else:
            result["reason"] = f"Expected output '{expected_output}' not found in response"
        return result

    # ── Directory Brute Force ──────────────────────────────────────

    def check_dir(self, response: requests.Response, baseline_hash: str) -> bool:
        """Verify directory finding is real, not a soft 404."""
        if response is None or response.status_code in (404, 403, 400, 500):
            return False
        import hashlib
        current_hash = hashlib.md5(
            f"{response.status_code}{len(response.content)}".encode()
        ).hexdigest()
        return current_hash != baseline_hash and response.status_code == 200

    # ── CRLF Injection ────────────────────────────────────────────

    def check_crlf_detailed(self, baseline_resp: requests.Response,
                            payload_resp: requests.Response,
                            expected_header: str = "X-Venom") -> Dict:
        """Verify CRLF injection by checking raw headers for injected header."""
        result = {"is_real": False, "reason": "", "proof_data": {}}
        if payload_resp is None:
            result["reason"] = "No response received"
            return result

        # Check if the expected header appears in the payload response
        has_header = expected_header.lower() in {
            k.lower() for k in payload_resp.headers
        }
        baseline_has = baseline_resp and expected_header.lower() in {
            k.lower() for k in baseline_resp.headers
        }

        if has_header and not baseline_has:
            result["is_real"] = True
            result["reason"] = (
                f"Injected header '{expected_header}' found in payload response "
                f"but NOT in baseline response headers"
            )
            result["proof_data"] = {
                "injected_header": True,
                "injected_header_name": expected_header,
                "baseline_missing_pattern": True,
            }
        elif has_header and baseline_has:
            result["reason"] = f"Header '{expected_header}' exists in both baseline and payload"
        else:
            result["reason"] = f"Header '{expected_header}' not found in payload response"

        return result

    # ── XXE (XML External Entity) ─────────────────────────────────

    XXE_INDICATORS = [
        (r"root:.*:0:0:", "Unix /etc/passwd via XXE"),
        (r"\[boot loader\]", "Windows boot.ini via XXE"),
        (r"<!\[CDATA\[", "CDATA section (possible XXE processing)"),
    ]

    def check_xxe_detailed(self, baseline_resp: requests.Response,
                           payload_resp: requests.Response) -> Dict:
        """Verify XXE by checking for file content indicators."""
        result = {"is_real": False, "reason": "", "proof_data": {}}
        if payload_resp is None:
            result["reason"] = "No response received"
            return result

        for pattern, description in self.XXE_INDICATORS:
            match = re.search(pattern, payload_resp.text, re.IGNORECASE)
            if match:
                baseline_has = baseline_resp and re.search(
                    pattern, baseline_resp.text, re.IGNORECASE
                )
                if not baseline_has:
                    result["is_real"] = True
                    result["reason"] = (
                        f"XXE indicator '{description}' ({match.group()[:60]}) "
                        f"found in payload response but NOT in baseline"
                    )
                    result["proof_data"] = {
                        "xxe_content": match.group()[:100],
                        "indicator": description,
                        "baseline_missing_pattern": True,
                    }
                    return result

        result["reason"] = "No XXE indicators found in response"
        return result

    # ── Open Redirect ─────────────────────────────────────────────

    def check_open_redirect_detailed(self, payload_resp: requests.Response,
                                     injected_domain: str) -> Dict:
        """Verify open redirect by checking Location header."""
        result = {"is_real": False, "reason": "", "proof_data": {}}
        if payload_resp is None:
            result["reason"] = "No response received"
            return result

        location = payload_resp.headers.get("Location", "")
        if injected_domain.lower() in location.lower():
            result["is_real"] = True
            result["reason"] = (
                f"Redirect Location header contains injected domain "
                f"'{injected_domain}': {location}"
            )
            result["proof_data"] = {
                "redirect_injection": True,
                "injected_domain": injected_domain,
                "location_header": location,
            }
        elif payload_resp.status_code in (301, 302, 303, 307, 308):
            result["reason"] = (
                f"Redirect detected but Location '{location}' does not "
                f"contain injected domain '{injected_domain}'"
            )
        else:
            result["reason"] = f"No redirect (status {payload_resp.status_code})"

        return result
