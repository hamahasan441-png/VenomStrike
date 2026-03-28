"""HTML/JSON report generator with executive summary."""
# For authorized security testing only.
import json
import os
import time
from typing import List, Dict
from config import REPORTS_DIR, SEVERITY_COLORS, VERSION


def ensure_reports_dir():
    os.makedirs(REPORTS_DIR, exist_ok=True)


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


def generate_html_report(scan_id: str, target: str, findings: List[Dict], summary: Dict) -> str:
    """Generate professional HTML pentest report."""
    ensure_reports_dir()
    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "Info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    findings_html = ""
    for i, finding in enumerate(findings, 1):
        sev = finding.get("severity", "Info")
        color = SEVERITY_COLORS.get(sev, "#888")
        findings_html += f"""
        <div class="finding" id="finding-{i}">
            <div class="finding-header" style="border-left: 4px solid {color}">
                <span class="severity-badge" style="background:{color}">{sev}</span>
                <h3>{finding.get('vuln_type', 'Unknown')}</h3>
                <span class="confidence">Confidence: {finding.get('confidence', 0)}%</span>
            </div>
            <div class="finding-body">
                <table>
                    <tr><td><b>URL</b></td><td><code>{finding.get('url', '')}</code></td></tr>
                    <tr><td><b>Parameter</b></td><td><code>{finding.get('param', '')}</code></td></tr>
                    <tr><td><b>Payload</b></td><td><code>{finding.get('payload', '')}</code></td></tr>
                    <tr><td><b>CWE</b></td><td>{finding.get('cwe', '')}</td></tr>
                    <tr><td><b>CVSS</b></td><td>{finding.get('cvss', 0)}</td></tr>
                    <tr><td><b>OWASP</b></td><td>{finding.get('owasp', '')}</td></tr>
                </table>
            </div>
        </div>
        """
    
    html = f"""<!DOCTYPE html>
<html>
<head>
<title>VenomStrike Report - {target}</title>
<style>
body {{ font-family: 'Courier New', monospace; background: #0a0a0a; color: #e0e0e0; margin: 0; padding: 20px; }}
h1 {{ color: #ff0040; text-shadow: 0 0 10px #ff0040; }}
h2 {{ color: #ff3366; border-bottom: 1px solid #ff0040; padding-bottom: 5px; }}
h3 {{ color: #e0e0e0; }}
.finding {{ background: #111; border: 1px solid rgba(255,0,64,0.3); margin: 20px 0; border-radius: 4px; overflow: hidden; }}
.finding-header {{ padding: 15px; background: rgba(255,0,64,0.1); display: flex; align-items: center; gap: 15px; }}
.finding-body {{ padding: 15px; }}
.severity-badge {{ padding: 4px 12px; border-radius: 3px; color: #000; font-weight: bold; font-size: 12px; }}
.confidence {{ color: #00ff41; margin-left: auto; }}
table {{ border-collapse: collapse; width: 100%; }}
td {{ padding: 6px 10px; border: 1px solid #333; }}
td:first-child {{ width: 120px; color: #ff3366; font-weight: bold; }}
code {{ background: #1a1a1a; padding: 2px 5px; border-radius: 2px; color: #ff6600; }}
.summary {{ background: #111; padding: 20px; border: 1px solid rgba(255,0,64,0.3); margin: 20px 0; border-radius: 4px; }}
.disclaimer {{ background: rgba(255,0,64,0.1); border: 1px solid #ff0040; padding: 15px; margin: 20px 0; border-radius: 4px; color: #ff6600; }}
</style>
</head>
<body>
<h1>🗡️ VenomStrike Security Report</h1>
<div class="disclaimer">
⚠️ This report is for authorized security testing only. Handle with care.
</div>
<div class="summary">
    <h2>Executive Summary</h2>
    <p><b>Target:</b> {target}</p>
    <p><b>Scan ID:</b> {scan_id}</p>
    <p><b>Generated:</b> {time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())}</p>
    <p><b>Total Findings:</b> {len(findings)}</p>
    <p><b>Critical:</b> {severity_counts.get('Critical', 0)} | 
       <b>High:</b> {severity_counts.get('High', 0)} | 
       <b>Medium:</b> {severity_counts.get('Medium', 0)} | 
       <b>Low:</b> {severity_counts.get('Low', 0)}</p>
    <p><b>Security Score:</b> {summary.get('security_score', 0)}/100</p>
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
    """Calculate a security score based on findings."""
    score = 100
    deductions = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Info": 0}
    for finding in findings:
        sev = finding.get("severity", "Info")
        score -= deductions.get(sev, 0)
    return max(0, score)
