"""
VenomStrike Flask Web Application
For authorized security testing only.
"""
import os
import sys
import json
import threading
import time

sys.path.insert(0, os.path.dirname(__file__))

import urllib3
urllib3.disable_warnings()

from flask import (Flask, render_template, request, redirect, url_for,
                   flash, jsonify, send_file, g)
from flask_wtf.csrf import CSRFProtect

from config import (FLASK_SECRET_KEY, FLASK_DEBUG, FLASK_HOST, FLASK_PORT,
                    REPORTS_DIR, VERSION)
from core.database import init_db, get_all_scans, get_scan, get_findings, delete_scan
from core.auth_check import check_web_authorization, validate_target_url
from core.session import SessionManager
from core.engine import ScanEngine
from core.reporter import generate_html_report, generate_json_report
from core.logger import log_info, log_error

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
app.config["WTF_CSRF_ENABLED"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

csrf = CSRFProtect(app)

# In-memory scan status store
scan_status = {}
scan_lock = threading.Lock()

# Initialize DB on startup
init_db()


def get_or_create_scan_status(scan_id):
    with scan_lock:
        if scan_id not in scan_status:
            scan_status[scan_id] = {
                "status": "running", "progress": 0, "message": "Initializing...",
                "findings_count": 0, "findings": []
            }
        return scan_status[scan_id]


@app.template_filter('strftime')
def strftime_filter(ts):
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(ts)))
    except Exception:
        return str(ts)


@app.template_filter('urlencode')
def urlencode_filter(s):
    from urllib.parse import quote
    return quote(str(s))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def start_scan():
    target = request.form.get("target", "").strip()
    scan_mode = request.form.get("scan_mode", "auto")
    threads = int(request.form.get("threads", 10))
    cookie = request.form.get("cookie", "")
    proxy = request.form.get("proxy", "")
    authorized = request.form.get("authorized") == "on"
    learning_mode = request.form.get("learning_mode") == "on"
    depth = request.form.get("depth", "standard")

    # Authorization check
    if not check_web_authorization(authorized, target):
        flash("You must confirm authorization before scanning.", "error")
        return redirect(url_for("index"))

    # Validate URL
    valid, target_url = validate_target_url(target)
    if not valid:
        flash(f"Invalid target URL: {target_url}", "error")
        return redirect(url_for("index"))

    # Build session manager
    session_mgr = SessionManager(cookie=cookie, proxy=proxy)

    # Create scan engine with callback for real-time updates
    def scan_callback(event_type, data):
        pass  # Updates handled in engine

    engine = ScanEngine(
        session_manager=session_mgr,
        threads=min(threads, 50),
        learning_mode=learning_mode,
        depth=depth,
    )

    # Run scan in background thread
    def run_scan_thread():
        try:
            CATEGORIES = {"injection", "client_side", "server_side", "auth", "logic", "advanced"}
            if scan_mode == "auto":
                result = engine.run_auto_scan(target_url)
            elif scan_mode in CATEGORIES:
                result = engine.run_category_scan(target_url, scan_mode)
            else:
                result = engine.run_auto_scan(target_url)

            if learning_mode and result.get("findings"):
                try:
                    from debugger.vuln_debugger import VulnDebugger
                    debugger = VulnDebugger()
                    result["findings"] = debugger.debug_all(result["findings"])
                except Exception as e:
                    log_error(f"Learning mode error: {e}")

        except Exception as e:
            log_error(f"Scan thread error: {e}")

    scan_thread = threading.Thread(target=run_scan_thread, daemon=True)
    scan_thread.start()

    # Wait briefly for scan to initialize and get ID
    time.sleep(0.5)
    scan_id = engine.scan_id

    if not scan_id:
        flash("Failed to start scan.", "error")
        return redirect(url_for("index"))

    return redirect(url_for("results", scan_id=scan_id))


@app.route("/results/<scan_id>")
def results(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        flash("Scan not found.", "error")
        return redirect(url_for("history"))

    findings = get_findings(scan_id)
    summary = scan.get("summary", {})

    return render_template("results.html", scan={
        "scan_id": scan_id,
        "target": scan["target"],
        "status": scan["status"],
        "started_at": scan.get("started_at"),
    }, findings=findings, summary=summary)


@app.route("/history")
def history():
    scans = get_all_scans()
    return render_template("history.html", scans=scans)


@app.route("/scan/<scan_id>/delete", methods=["POST"])
def delete_scan_route(scan_id):
    delete_scan(scan_id)
    flash("Scan deleted.", "success")
    return redirect(url_for("history"))


@app.route("/report/<scan_id>/html")
def report_html(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        flash("Scan not found.", "error")
        return redirect(url_for("history"))
    findings = get_findings(scan_id)
    summary = scan.get("summary", {})
    path = generate_html_report(scan_id, scan["target"], findings, summary)
    return send_file(path, mimetype="text/html", as_attachment=False)


@app.route("/report/<scan_id>/json")
def report_json(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    findings = get_findings(scan_id)
    summary = scan.get("summary", {})
    path = generate_json_report(scan_id, scan["target"], findings, summary)
    return send_file(path, mimetype="application/json", as_attachment=True,
                     download_name=f"venomstrike-{scan_id[:8]}.json")


@app.route("/api/scan/<scan_id>/status")
def api_scan_status(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Not found"}), 404
    findings = get_findings(scan_id)
    return jsonify({
        "scan_id": scan_id,
        "status": scan["status"],
        "target": scan["target"],
        "summary": scan.get("summary", {}),
        "findings_count": len(findings),
        "progress": 100 if scan["status"] == "completed" else 50,
        "message": f"Scan {scan['status']}",
    })


@app.route("/api/findings/<scan_id>")
def api_findings(scan_id):
    findings = get_findings(scan_id)
    return jsonify({"findings": findings, "count": len(findings)})


@app.route("/learning")
def learning():
    return render_template("learning.html")


@app.route("/api/integrations")
def api_integrations():
    """Show available tool integrations and their status."""
    from config import (NMAP_ENABLED, SHODAN_API_KEY, ZAP_ENABLED,
                        NUCLEI_ENABLED, NVD_API_KEY,
                        AMASS_ENABLED, WAPPALYZER_ENABLED)
    integrations = {
        "nmap": {"enabled": NMAP_ENABLED, "description": "Network port scanning & service detection"},
        "shodan": {"enabled": bool(SHODAN_API_KEY), "description": "Passive host reconnaissance"},
        "zap": {"enabled": ZAP_ENABLED, "description": "OWASP ZAP automated scanning"},
        "nuclei": {"enabled": NUCLEI_ENABLED, "description": "Template-based vulnerability scanning"},
        "cve_lookup": {"enabled": bool(NVD_API_KEY), "description": "CVE/NVD vulnerability enrichment"},
        "amass": {"enabled": AMASS_ENABLED, "description": "Subdomain enumeration & DNS discovery"},
        "wappalyzer": {"enabled": WAPPALYZER_ENABLED, "description": "Technology fingerprinting & detection"},
    }
    return jsonify({"integrations": integrations})


@app.route("/learning/<vuln_type>")
def learning_detail(vuln_type):
    try:
        from debugger.learning_resources import LearningResources
        from debugger.code_fixer import CodeFixer
        from debugger.prevention_guide import PreventionGuide
        from debugger.attack_explainer import AttackExplainer
        
        lr = LearningResources()
        cf = CodeFixer()
        pg = PreventionGuide()
        ae = AttackExplainer()
        
        resources = lr.get_resources(vuln_type)
        fix = cf.get_fix({"vuln_type": vuln_type})
        prevention = pg.get_guide({"vuln_type": vuln_type})
        explanation = ae.explain({"vuln_type": vuln_type})
        
        return jsonify({
            "vuln_type": vuln_type,
            "resources": resources,
            "fix": fix,
            "prevention": prevention,
            "explanation": explanation,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.errorhandler(404)
def not_found(e):
    return render_template("index.html"), 404


@app.errorhandler(500)
def server_error(e):
    log_error(f"Server error: {e}")
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    log_info(f"Starting VenomStrike Web UI on http://{FLASK_HOST}:{FLASK_PORT}")
    log_info("FOR AUTHORIZED SECURITY TESTING ONLY")
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
