"""Structured evidence collection and proof chain for vulnerability findings.
For authorized security testing only.

Every finding must include machine-verifiable proof that the vulnerability is real,
not just a pattern match or heuristic guess.  The Evidence dataclass captures:

 - The original (baseline) request/response
 - The payload request/response
 - A human-readable proof_description explaining *why* this is a real vuln
 - A verification_status (unverified / confirmed / likely / suspicious / false_positive)
 - Optional re-test results

Quantum Edition (v4.0) adds:
 - verification_chain: ordered list of verification steps performed, each with
   its own method name, result, and timestamp.
 - entropy_analysis: response entropy deltas to detect structural changes.
 - cross_correlation: whether correlated findings boost confidence.
 - statistical_summary: z-score and p-value for measurement-based detections.
"""
import time
import hashlib
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict


# ── Verification statuses ──────────────────────────────────────────────
VERIFIED_CONFIRMED = "confirmed"      # Re-tested and confirmed ≥2/3 times
VERIFIED_LIKELY = "likely"            # Strong single-pass evidence
VERIFIED_SUSPICIOUS = "suspicious"    # Heuristic match, not confirmed
VERIFIED_UNVERIFIED = "unverified"    # Not yet validated
VERIFIED_FALSE_POSITIVE = "false_positive"  # Determined to be FP


@dataclass
class RequestTrace:
    """Capture of a single HTTP request/response for evidence."""
    method: str = ""
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    status_code: int = 0
    response_length: int = 0
    response_snippet: str = ""
    response_hash: str = ""
    elapsed_seconds: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class EvidencePackage:
    """Complete evidence package for a vulnerability finding."""
    # What was tested
    vuln_type: str = ""
    tested_url: str = ""
    tested_param: str = ""
    tested_payload: str = ""

    # Baseline (normal) request
    baseline: Optional[RequestTrace] = None

    # Payload (exploit) request
    payload_request: Optional[RequestTrace] = None

    # Proof — human-readable explanation of why this is real
    proof_description: str = ""

    # Proof data — structured evidence items
    proof_data: Dict[str, Any] = field(default_factory=dict)

    # Verification
    verification_status: str = VERIFIED_UNVERIFIED
    verification_details: str = ""
    retest_results: List[Dict] = field(default_factory=list)
    retest_confirmations: int = 0
    retest_attempts: int = 0

    # Deduplication
    fingerprint: str = ""

    # Raw evidence — full request/response capture for audit
    raw_headers: str = ""

    # Exploitability & remediation
    exploitability_description: str = ""
    remediation_guidance: str = ""

    # Quantum verification chain (v4.0)
    verification_chain: List[Dict] = field(default_factory=list)
    entropy_analysis: Dict[str, Any] = field(default_factory=dict)
    cross_correlation: Dict[str, Any] = field(default_factory=dict)
    statistical_summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        d = {
            "vuln_type": self.vuln_type,
            "tested_url": self.tested_url,
            "tested_param": self.tested_param,
            "tested_payload": self.tested_payload,
            "proof_description": self.proof_description,
            "proof_data": self.proof_data,
            "verification_status": self.verification_status,
            "verification_details": self.verification_details,
            "retest_confirmations": self.retest_confirmations,
            "retest_attempts": self.retest_attempts,
            "fingerprint": self.fingerprint,
        }
        if self.raw_headers:
            d["raw_headers"] = self.raw_headers
        if self.exploitability_description:
            d["exploitability_description"] = self.exploitability_description
        if self.remediation_guidance:
            d["remediation_guidance"] = self.remediation_guidance
        if self.baseline:
            d["baseline"] = self.baseline.to_dict()
        if self.payload_request:
            d["payload_request"] = self.payload_request.to_dict()
        if self.retest_results:
            d["retest_results"] = self.retest_results
        if self.verification_chain:
            d["verification_chain"] = self.verification_chain
        if self.entropy_analysis:
            d["entropy_analysis"] = self.entropy_analysis
        if self.cross_correlation:
            d["cross_correlation"] = self.cross_correlation
        if self.statistical_summary:
            d["statistical_summary"] = self.statistical_summary
        return d

    def compute_fingerprint(self) -> str:
        """Generate dedup fingerprint: same vuln_type + url + param = same finding."""
        raw = f"{self.vuln_type}|{self.tested_url}|{self.tested_param}"
        self.fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:16]
        return self.fingerprint


def capture_request_trace(
    response,
    method: str = "",
    url: str = "",
    body: str = "",
    elapsed: float = 0.0,
) -> RequestTrace:
    """Build a RequestTrace from a requests.Response object."""
    if response is None:
        return RequestTrace(method=method, url=url, body=body)
    snippet = response.text[:500] if response.text else ""
    resp_hash = hashlib.md5(
        f"{response.status_code}{len(response.content)}{snippet}".encode()
    ).hexdigest()

    # Calculate elapsed time clearly
    if elapsed:
        elapsed_secs = elapsed
    elif hasattr(response, "elapsed") and response.elapsed:
        elapsed_secs = response.elapsed.total_seconds()
    else:
        elapsed_secs = 0.0

    # Extract method/url from request if not provided
    req_method = method or (response.request.method if response.request else "")
    req_url = url or (response.request.url if response.request else "")
    req_headers = dict(response.request.headers) if response.request else {}

    return RequestTrace(
        method=req_method,
        url=req_url,
        headers=req_headers,
        body=body,
        status_code=response.status_code,
        response_length=len(response.content),
        response_snippet=snippet,
        response_hash=resp_hash,
        elapsed_seconds=elapsed_secs,
    )


def build_proof_description(vuln_type: str, proof_data: Dict) -> str:
    """Generate a human-readable proof explanation from structured proof data."""
    parts = []

    if "error_pattern" in proof_data:
        parts.append(
            f"SQL error pattern '{proof_data['error_pattern']}' appeared in the response "
            f"ONLY when the payload was injected (not present in baseline)."
        )

    if "reflected_payload" in proof_data:
        parts.append(
            f"The injected payload was reflected UNESCAPED in the response body. "
            f"Dangerous content '{proof_data.get('reflected_part', '')}' found in output."
        )

    if "file_content_indicator" in proof_data:
        parts.append(
            f"File content indicator '{proof_data['file_content_indicator']}' found in response, "
            f"confirming local file read via path traversal."
        )

    if "timing_diff" in proof_data:
        baseline_time = proof_data.get("baseline_time", 0)
        payload_time = proof_data.get("timing_diff", 0)
        parts.append(
            f"Time-based detection: baseline responded in {baseline_time:.1f}s, "
            f"payload response took {payload_time:.1f}s "
            f"(delta: {payload_time - baseline_time:.1f}s), "
            f"exceeding the sleep threshold."
        )

    if "command_output" in proof_data:
        parts.append(
            f"Command output pattern '{proof_data['command_output']}' detected in response, "
            f"confirming OS command execution."
        )

    if "response_diff_percent" in proof_data:
        parts.append(
            f"Response differed by {proof_data['response_diff_percent']:.1f}% from baseline "
            f"(baseline: {proof_data.get('baseline_length', 0)} bytes, "
            f"payload: {proof_data.get('payload_length', 0)} bytes)."
        )

    if "metadata_content" in proof_data:
        parts.append(
            f"Cloud metadata content detected: '{proof_data['metadata_content'][:100]}'. "
            f"This confirms SSRF access to internal metadata service."
        )

    if "baseline_missing_pattern" in proof_data:
        parts.append(
            f"The pattern was NOT present in the baseline response, "
            f"confirming the payload triggered the behavior."
        )

    if "injected_header" in proof_data:
        parts.append(
            f"CRLF injection confirmed: injected header "
            f"'{proof_data.get('injected_header_name', '')}' appeared in the raw "
            f"response headers, absent from the baseline."
        )

    if "xxe_content" in proof_data:
        parts.append(
            f"XXE confirmed: external entity content "
            f"'{proof_data['xxe_content'][:80]}' was resolved and included in "
            f"the response, proving XML entity processing."
        )

    if "redirect_injection" in proof_data:
        parts.append(
            f"Open redirect confirmed: the Location header points to "
            f"injected domain '{proof_data.get('injected_domain', '')}'."
        )

    if "nosql_auth_bypass" in proof_data:
        parts.append(
            f"NoSQL injection confirmed: authentication was bypassed — "
            f"baseline status {proof_data.get('baseline_status', '?')} changed to "
            f"{proof_data.get('payload_status', '?')} with operator payload."
        )

    if "confirmation_markers" in proof_data:
        parts.append(
            f"Multi-stage confirmation: two independent markers both triggered "
            f"the same behavioural change, ruling out coincidence."
        )

    if "triple_confirmation" in proof_data:
        parts.append(
            f"Quantum triple-marker confirmation: three independent markers ALL "
            f"triggered the same behavioural change at the same injection point. "
            f"Baseline was clean. This is the highest assurance level."
        )

    if "entropy_delta" in proof_data:
        parts.append(
            f"Entropy analysis: response entropy shifted by "
            f"{proof_data['entropy_delta']:.4f} bits "
            f"(baseline: {proof_data.get('baseline_entropy', 0):.4f}, "
            f"payload: {proof_data.get('payload_entropy', 0):.4f}), "
            f"indicating a structural change in the response content."
        )

    if "cross_correlated" in proof_data and proof_data["cross_correlated"]:
        parts.append(
            f"Cross-correlation: {proof_data.get('cluster_size', 0)} findings of "
            f"the same vulnerability type were detected across different parameters "
            f"on the same endpoint, providing corroborating evidence."
        )

    if "z_score" in proof_data:
        parts.append(
            f"Statistical analysis: z-score={proof_data['z_score']:.2f} "
            f"(p {'< 0.05 — statistically significant' if proof_data.get('p_significant') else '>= 0.05'}), "
            f"based on {proof_data.get('sample_count', 0)} independent measurements."
        )

    if not parts:
        parts.append(f"Vulnerability detected via {vuln_type} testing.")

    return " ".join(parts)
