"""HTML/JSON report generator with evidence display and verification badges."""
# For authorized security testing only.
import json
import os
import time
import html as html_module
from typing import List, Dict
from config import REPORTS_DIR, SEVERITY_COLORS, VERSION


def ensure_reports_dir():
    os.makedirs(REPORTS_DIR, exist_ok=True)


def _escape(text: str) -> str:
    """HTML-escape a string for safe rendering in reports."""
    return html_module.escape(str(text)) if text else ""


def generate_json_report(scan_id: str, target: str, findings: List[Dict], summary: Dict) -> str:
    """Generate JSON report."""
    ensure_reports_dir()
    report = {
        "tool": "VenomStrike",
        "version": VERSION,
        "scan_id": scan_id,
        "target": target,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": summary,
        "findings": findings,
    }
    filepath = os.path.join(REPORTS_DIR, f"{scan_id}.json")
    with open(filepath, "w") as f:
        json.dump(report, f, indent=2, default=str)
    return filepath


def _verification_badge(status: str) -> str:
    """Generate an HTML badge for verification status."""
    colors = {
        "confirmed": ("#00ff41", "CONFIRMED"),
        "likely": ("#66ff66", "LIKELY"),
        "suspicious": ("#ffcc00", "SUSPICIOUS"),
        "unverified": ("#ff6600", "UNVERIFIED"),
        "false_positive": ("#ff0040", "FALSE POSITIVE"),
    }
    color, label = colors.get(status, ("#888", status.upper()))
    return (
        f'<span class="verify-badge" style="background:{color};color:#000;'
        f'padding:2px 8px;border-radius:3px;font-size:11px;font-weight:bold">'
        f'{label}</span>'
    )


def _render_evidence(evidence) -> str:
    """Render the evidence section for a finding."""
    if not evidence:
        return '<p class="no-evidence">No evidence collected</p>'

    if not isinstance(evidence, dict):
        return f'<pre>{_escape(str(evidence))}</pre>'

    parts = []

    # Proof description (most important)
    proof = evidence.get("proof_description", "")
    if proof:
        parts.append(f'<div class="proof-box"><b>Proof:</b> {_escape(proof)}</div>')

    # Verification details
    v_status = evidence.get("verification_status", "")
    v_details = evidence.get("verification_details", "")
    if v_status:
        parts.append(
            f'<div class="verify-box">'
            f'<b>Verification:</b> {_verification_badge(v_status)} '
            f'{_escape(v_details)}</div>'
        )

    # Re-test results
    retests = evidence.get("retest_confirmations", 0)
    attempts = evidence.get("retest_attempts", 0)
    if attempts > 0:
        parts.append(
            f'<div class="retest-box">'
            f'<b>Re-test:</b> {retests}/{attempts} confirmations</div>'
        )

    # Baseline comparison
    baseline = evidence.get("baseline")
    payload_req = evidence.get("payload_request")
    if baseline and isinstance(baseline, dict):
        parts.append(
            f'<div class="baseline-box">'
            f'<b>Baseline:</b> HTTP {baseline.get("status_code", "?")} '
            f'({baseline.get("response_length", 0)} bytes, '
            f'{baseline.get("elapsed_seconds", 0):.2f}s)'
            f'</div>'
        )
    if payload_req and isinstance(payload_req, dict):
        parts.append(
            f'<div class="payload-box">'
            f'<b>Payload Response:</b> HTTP {payload_req.get("status_code", "?")} '
            f'({payload_req.get("response_length", 0)} bytes, '
            f'{payload_req.get("elapsed_seconds", 0):.2f}s)'
            f'</div>'
        )

    # Proof data table
    proof_data = evidence.get("proof_data", {})
    if proof_data:
        rows = ""
        for k, v in proof_data.items():
            rows += f'<tr><td><code>{_escape(k)}</code></td><td>{_escape(str(v))}</td></tr>'
        parts.append(
            f'<div class="proof-data"><b>Evidence Details:</b>'
            f'<table class="evidence-table">{rows}</table></div>'
        )

    # Response snippet
    snippet = ""
    if payload_req and isinstance(payload_req, dict):
        snippet = payload_req.get("response_snippet", "")
    if not snippet and isinstance(evidence, dict):
        snippet = evidence.get("response_snippet", "") or evidence.get("snippet", "")
    if snippet:
        parts.append(
            f'<div class="snippet-box">'
            f'<b>Response Snippet:</b><pre>{_escape(str(snippet)[:400])}</pre></div>'
        )

    return "\n".join(parts) if parts else '<p class="no-evidence">No structured evidence</p>'


def generate_html_report(scan_id: str, target: str, findings: List[Dict], summary: Dict) -> str:
    """Generate professional HTML pentest report with evidence display."""
    ensure_reports_dir()
    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "Info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    verified = summary.get("verified_findings", 0)
    suspicious = summary.get("suspicious_findings", 0)

    findings_html = ""
    for i, finding in enumerate(findings, 1):
        sev = finding.get("severity", "Info")
        color = SEVERITY_COLORS.get(sev, "#888")
        v_status = finding.get("verification_status", "unverified")
        proof_desc = finding.get("proof_description", "")
        evidence = finding.get("evidence", {})

        findings_html += f"""
        <div class="finding" id="finding-{i}">
            <div class="finding-header" style="border-left: 4px solid {color}">
                <span class="severity-badge" style="background:{color}">{sev}</span>
                <h3>{_escape(finding.get('vuln_type', 'Unknown'))}</h3>
                {_verification_badge(v_status)}
                <span class="confidence">Confidence: {finding.get('confidence', 0)}%</span>
            </div>
            <div class="finding-body">
                <table>
                    <tr><td><b>URL</b></td><td><code>{_escape(finding.get('url', ''))}</code></td></tr>
                    <tr><td><b>Parameter</b></td><td><code>{_escape(finding.get('param', ''))}</code></td></tr>
                    <tr><td><b>Payload</b></td><td><code>{_escape(finding.get('payload', ''))}</code></td></tr>
                    <tr><td><b>CWE</b></td><td>{_escape(finding.get('cwe', ''))}</td></tr>
                    <tr><td><b>CVSS</b></td><td>{finding.get('cvss', 0)}</td></tr>
                    <tr><td><b>OWASP</b></td><td>{_escape(finding.get('owasp', ''))}</td></tr>
                </table>
                <div class="evidence-section">
                    <h4>Evidence & Proof</h4>
                    {_render_evidence(evidence)}
                </div>
            </div>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html>
<head>
<title>VenomStrike Report - {_escape(target)}</title>
<style>
body {{ font-family: 'Courier New', monospace; background: #0a0a0a; color: #e0e0e0; margin: 0; padding: 20px; }}
h1 {{ color: #ff0040; text-shadow: 0 0 10px #ff0040; }}
h2 {{ color: #ff3366; border-bottom: 1px solid #ff0040; padding-bottom: 5px; }}
h3 {{ color: #e0e0e0; margin: 0; }}
h4 {{ color: #00ff41; margin-top: 15px; }}
.finding {{ background: #111; border: 1px solid rgba(255,0,64,0.3); margin: 20px 0; border-radius: 4px; overflow: hidden; }}
.finding-header {{ padding: 15px; background: rgba(255,0,64,0.1); display: flex; align-items: center; gap: 15px; flex-wrap: wrap; }}
.finding-body {{ padding: 15px; }}
.severity-badge {{ padding: 4px 12px; border-radius: 3px; color: #000; font-weight: bold; font-size: 12px; }}
.confidence {{ color: #00ff41; margin-left: auto; }}
table {{ border-collapse: collapse; width: 100%; }}
td {{ padding: 6px 10px; border: 1px solid #333; }}
td:first-child {{ width: 120px; color: #ff3366; font-weight: bold; }}
code {{ background: #1a1a1a; padding: 2px 5px; border-radius: 2px; color: #ff6600; word-break: break-all; }}
pre {{ background: #0d0d0d; padding: 10px; border: 1px solid #333; border-radius: 4px; overflow-x: auto; color: #aaa; font-size: 12px; white-space: pre-wrap; }}
.summary {{ background: #111; padding: 20px; border: 1px solid rgba(255,0,64,0.3); margin: 20px 0; border-radius: 4px; }}
.disclaimer {{ background: rgba(255,0,64,0.1); border: 1px solid #ff0040; padding: 15px; margin: 20px 0; border-radius: 4px; color: #ff6600; }}
.evidence-section {{ margin-top: 15px; padding: 15px; background: #0a0a0a; border: 1px solid #222; border-radius: 4px; }}
.proof-box {{ background: rgba(0,255,65,0.05); border-left: 3px solid #00ff41; padding: 10px; margin: 8px 0; }}
.verify-box {{ padding: 8px 0; }}
.retest-box {{ padding: 8px 0; color: #aaa; }}
.baseline-box, .payload-box {{ padding: 4px 0; color: #888; font-size: 13px; }}
.snippet-box {{ margin-top: 10px; }}
.proof-data {{ margin-top: 10px; }}
.evidence-table {{ font-size: 12px; margin-top: 5px; }}
.evidence-table td {{ padding: 3px 8px; }}
.no-evidence {{ color: #666; font-style: italic; }}
.verify-badge {{ display: inline-block; }}
.stats {{ display: flex; gap: 20px; margin-top: 10px; }}
.stat-card {{ background: #1a1a1a; padding: 10px 15px; border-radius: 4px; text-align: center; }}
.stat-num {{ font-size: 24px; font-weight: bold; }}
</style>
</head>
<body>
<h1>&#128481; VenomStrike Security Report</h1>
<div class="disclaimer">
&#9888;&#65039; This report is for authorized security testing only. Handle with care.
</div>
<div class="summary">
    <h2>Executive Summary</h2>
    <p><b>Target:</b> {_escape(target)}</p>
    <p><b>Scan ID:</b> {scan_id}</p>
    <p><b>Generated:</b> {time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())}</p>
    <p><b>Total Findings:</b> {len(findings)}</p>
    <p><b>Critical:</b> {severity_counts.get('Critical', 0)} |
       <b>High:</b> {severity_counts.get('High', 0)} |
       <b>Medium:</b> {severity_counts.get('Medium', 0)} |
       <b>Low:</b> {severity_counts.get('Low', 0)}</p>
    <p><b>Security Score:</b> {summary.get('security_score', 0)}/100</p>
    <div class="stats">
        <div class="stat-card">
            <div class="stat-num" style="color:#00ff41">{verified}</div>
            <div>Verified</div>
        </div>
        <div class="stat-card">
            <div class="stat-num" style="color:#ffcc00">{suspicious}</div>
            <div>Suspicious</div>
        </div>
        <div class="stat-card">
            <div class="stat-num" style="color:#ff0040">{severity_counts.get('Critical', 0)}</div>
            <div>Critical</div>
        </div>
    </div>
</div>
<h2>Findings ({len(findings)})</h2>
{findings_html}
</body>
</html>"""

    filepath = os.path.join(REPORTS_DIR, f"{scan_id}.html")
    with open(filepath, "w") as f:
        f.write(html)
    return filepath


def calculate_security_score(findings: List[Dict]) -> int:
    """Calculate a security score based on findings, weighted by verification status."""
    score = 100
    deductions = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Info": 0}
    verification_weights = {
        "confirmed": 1.0,
        "likely": 0.9,
        "suspicious": 0.5,
        "unverified": 0.7,
        "false_positive": 0.0,
    }
    for finding in findings:
        sev = finding.get("severity", "Info")
        v_status = finding.get("verification_status", "unverified")
        weight = verification_weights.get(v_status, 0.7)
        deduction = deductions.get(sev, 0) * weight
        score -= deduction
    return max(0, int(score))
