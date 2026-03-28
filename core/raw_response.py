"""Raw HTTP response analysis for injection evidence collection.
For authorized security testing only.
"""
import re
import hashlib
from typing import Dict, List, Optional, Tuple
import requests


class RawResponseAnalyzer:
    """Analyze raw HTTP responses for injection evidence.

    Goes beyond parsed response objects to detect:
    - Injected headers (CRLF)
    - Structural changes in HTML/JSON
    - Raw header line injection
    - Redirect manipulation
    """

    @staticmethod
    def extract_raw_headers(response: requests.Response) -> str:
        """Extract the raw header block as a string.

        Uses the response's raw data when available, otherwise
        reconstructs from the parsed headers dict.
        """
        if response is None:
            return ""
        lines = [f"HTTP/1.1 {response.status_code} {response.reason or ''}"]
        for key, value in response.headers.items():
            lines.append(f"{key}: {value}")
        return "\r\n".join(lines)

    @staticmethod
    def check_injected_header(response: requests.Response,
                               header_name: str) -> bool:
        """Check if a specific header was injected into the response.

        Looks for the header in the response headers dict.
        """
        if response is None:
            return False
        return header_name.lower() in {k.lower() for k in response.headers}

    @staticmethod
    def check_header_value(response: requests.Response,
                           header_name: str,
                           expected_value: str) -> bool:
        """Check if a header contains an expected injected value."""
        if response is None:
            return False
        for key, value in response.headers.items():
            if key.lower() == header_name.lower():
                if expected_value.lower() in value.lower():
                    return True
        return False

    @staticmethod
    def detect_redirect_injection(response: requests.Response,
                                   injected_domain: str) -> bool:
        """Check if a redirect Location header was manipulated."""
        if response is None:
            return False
        location = response.headers.get("Location", "")
        return injected_domain.lower() in location.lower()

    @staticmethod
    def detect_structure_change(baseline_text: str,
                                 payload_text: str,
                                 marker: str = "") -> Dict:
        """Detect structural changes between baseline and payload responses.

        Returns a dict with change indicators.
        """
        result = {
            "length_diff": abs(len(payload_text) - len(baseline_text)),
            "length_diff_percent": 0.0,
            "new_tags_found": False,
            "marker_reflected": False,
            "new_error_patterns": False,
        }

        max_len = max(len(baseline_text), len(payload_text), 1)
        result["length_diff_percent"] = (result["length_diff"] / max_len) * 100

        # Check for marker reflection
        if marker and marker in payload_text and marker not in baseline_text:
            result["marker_reflected"] = True

        # Check for new HTML tags in payload response
        baseline_tags = set(re.findall(r"<(\w+)", baseline_text[:5000]))
        payload_tags = set(re.findall(r"<(\w+)", payload_text[:5000]))
        new_tags = payload_tags - baseline_tags
        if new_tags:
            result["new_tags_found"] = True
            result["new_tags"] = list(new_tags)

        # Check for new error patterns
        error_patterns = [
            r"error", r"exception", r"warning", r"fatal",
            r"stack\s*trace", r"syntax\s*error", r"parse\s*error",
        ]
        for pattern in error_patterns:
            if (re.search(pattern, payload_text[:3000], re.IGNORECASE)
                    and not re.search(pattern, baseline_text[:3000], re.IGNORECASE)):
                result["new_error_patterns"] = True
                break

        return result

    @staticmethod
    def compute_body_hash(text: str) -> str:
        """Compute a hash of the response body for comparison."""
        return hashlib.sha256(text.encode(errors="replace")).hexdigest()[:16]

    @staticmethod
    def capture_full_evidence(response: requests.Response,
                               baseline: requests.Response = None) -> Dict:
        """Capture comprehensive evidence from a response for reporting.

        Returns a dict suitable for inclusion in EvidencePackage.proof_data.
        """
        if response is None:
            return {"error": "No response received"}

        evidence = {
            "status_code": response.status_code,
            "response_length": len(response.content),
            "content_type": response.headers.get("Content-Type", ""),
            "raw_headers": RawResponseAnalyzer.extract_raw_headers(response),
            "body_snippet": response.text[:1000],
            "body_hash": RawResponseAnalyzer.compute_body_hash(response.text),
        }

        if baseline:
            evidence["baseline_status"] = baseline.status_code
            evidence["baseline_length"] = len(baseline.content)
            evidence["baseline_hash"] = RawResponseAnalyzer.compute_body_hash(baseline.text)
            evidence["length_diff"] = abs(len(response.content) - len(baseline.content))

        return evidence
