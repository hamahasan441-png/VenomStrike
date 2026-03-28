#!/usr/bin/env python3
"""
VenomStrike CLI — Advanced Security Testing Framework
For authorized security testing only.

Usage:
    python venom.py -u https://target.com --mode auto
    python venom.py -u https://target.com --mode sqli --no-auth-check
    python venom.py -u https://target.com --mode xss --cookie "session=abc"
"""
import argparse
import signal
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(__file__))

import urllib3
urllib3.disable_warnings()

from core.logger import print_banner, log_info, log_error, log_success, log_warning
from core.auth_check import check_cli_authorization, validate_target_url
from core.session import SessionManager
from core.engine import ScanEngine
from core.reporter import generate_html_report, generate_json_report
from config import LEGAL_DISCLAIMER, VERSION

# Global engine reference for graceful shutdown via Ctrl+C
_active_engine: ScanEngine = None


def _handle_sigint(signum, frame):
    """Handle Ctrl+C by cancelling the active scan gracefully."""
    global _active_engine
    if _active_engine is not None:
        _active_engine.cancel()
    else:
        log_warning("Interrupted — exiting.")
        sys.exit(130)


def parse_args():
    parser = argparse.ArgumentParser(
        description="VenomStrike — Advanced Security Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python venom.py -u https://target.com --mode auto
  python venom.py -u https://target.com --mode injection --threads 20
  python venom.py -u https://target.com --mode sqli --cookie "session=abc123"
  python venom.py -u https://target.com --mode xss --proxy http://127.0.0.1:8080
  python venom.py -u https://target.com --mode all --learn --report html

⚠️  FOR AUTHORIZED TESTING ONLY — Ensure you have written permission
        """
    )
    
    # Target
    parser.add_argument("-u", "--url", required=True, help="Target URL to test")
    
    # Scan mode
    parser.add_argument(
        "--mode", default="auto",
        choices=["auto", "injection", "client_side", "server_side", "auth", "logic", "advanced",
                 "sqli", "nosql", "cmd", "ssti", "xxe", "ldap", "xpath",
                 "xss", "csrf", "clickjack", "cors", "open_redirect", "prototype_pollution",
                 "ssrf", "lfi", "rfi", "file_upload", "rce", "http_smuggling",
                 "auth_bypass", "jwt", "session", "oauth", "idor", "account_takeover",
                 "race_condition", "business_logic", "mass_assignment", "rate_limit",
                 "graphql", "websocket", "cache_poison", "crlf", "host_header", "subdomain_takeover"],
        help="Scan mode or specific module"
    )
    
    # HTTP options
    parser.add_argument("--cookie", default="", help="Cookie string (e.g., 'session=abc123')")
    parser.add_argument("--proxy", default="", help="HTTP proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--user-agent", default="", help="Custom User-Agent")
    parser.add_argument("--headers", default="", help="Custom headers as JSON string")
    parser.add_argument("--auth-user", default="", help="HTTP Basic auth username")
    parser.add_argument("--auth-pass", default="", help="HTTP Basic auth password")
    
    # Scan options
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (1-100, default: 10)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (1-120)")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests (seconds, 0-60)")
    
    # Output options
    parser.add_argument("--report", choices=["html", "json", "both", "none"], default="both", help="Report format")
    parser.add_argument("--output", default="", help="Output directory for reports")
    parser.add_argument("--learn", action="store_true", help="Enable learning mode (show fix code)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    # Authorization
    parser.add_argument("--no-auth-check", action="store_true", help="Skip authorization prompt (use with caution)")
    
    # Tool integrations
    parser.add_argument("--nmap", action="store_true", help="Enable Nmap port scanning integration")
    parser.add_argument("--nuclei", action="store_true", help="Enable Nuclei vulnerability scanning")
    parser.add_argument("--zap", action="store_true", help="Enable OWASP ZAP integration")
    parser.add_argument("--shodan", action="store_true", help="Enable Shodan passive recon")
    parser.add_argument("--cve-enrich", action="store_true", help="Enrich findings with CVE/NVD data")
    parser.add_argument("--no-integrations", action="store_true", help="Disable all external tool integrations")
    
    return parser.parse_args()


def main():
    global _active_engine
    print_banner()
    args = parse_args()
    
    # Register graceful shutdown handler
    signal.signal(signal.SIGINT, _handle_sigint)
    
    log_info(f"VenomStrike v{VERSION}")
    
    # Validate URL
    valid, target_url = validate_target_url(args.url)
    if not valid:
        log_error(f"Invalid target URL: {target_url}")
        sys.exit(1)
    
    # Validate numeric inputs
    threads = max(1, min(100, args.threads))
    if threads != args.threads:
        log_warning(f"Threads clamped to {threads} (valid range: 1-100)")
    timeout = max(1, min(120, args.timeout))
    if timeout != args.timeout:
        log_warning(f"Timeout clamped to {timeout}s (valid range: 1-120)")
    delay = max(0.0, min(60.0, args.delay))
    if delay != args.delay:
        log_warning(f"Delay clamped to {delay}s (valid range: 0-60)")
    
    # Authorization check
    if not args.no_auth_check:
        check_cli_authorization(target_url)
    else:
        log_warning("Authorization check skipped. Ensure you have permission to test this target.")
    
    # Build session
    headers = {}
    if args.headers:
        import json
        try:
            headers = json.loads(args.headers)
        except Exception:
            log_warning("Invalid headers JSON, ignoring")
    
    if args.user_agent:
        headers["User-Agent"] = args.user_agent
    
    session_mgr = SessionManager(
        cookie=args.cookie,
        headers=headers,
        proxy=args.proxy,
        auth_user=args.auth_user,
        auth_pass=args.auth_pass,
    )
    
    # Determine scan mode
    CATEGORIES = {"injection", "client_side", "server_side", "auth", "logic", "advanced"}
    MODULES = {
        "sqli", "nosql", "cmd", "ssti", "xxe", "ldap", "xpath",
        "xss", "csrf", "clickjack", "cors", "open_redirect", "prototype_pollution",
        "ssrf", "lfi", "rfi", "file_upload", "rce", "http_smuggling",
        "auth_bypass", "jwt", "session", "oauth", "idor", "account_takeover",
        "race_condition", "business_logic", "mass_assignment", "rate_limit",
        "graphql", "websocket", "cache_poison", "crlf", "host_header", "subdomain_takeover",
    }
    
    # Enable integrations based on CLI flags
    import os
    if args.nmap:
        os.environ["VS_NMAP_ENABLED"] = "true"
    if args.nuclei:
        os.environ["VS_NUCLEI_ENABLED"] = "true"
    if args.zap:
        os.environ["VS_ZAP_ENABLED"] = "true"
    if args.shodan and not os.environ.get("SHODAN_API_KEY"):
        log_warning("--shodan requires SHODAN_API_KEY env variable to be set")
    if args.cve_enrich and not os.environ.get("NVD_API_KEY"):
        log_warning("--cve-enrich requires NVD_API_KEY env variable to be set")

    # Reload config after setting env vars
    import importlib
    import config as _cfg
    importlib.reload(_cfg)

    engine = ScanEngine(
        session_manager=session_mgr,
        threads=threads,
        learning_mode=args.learn,
        enable_integrations=not args.no_integrations,
    )
    _active_engine = engine
    
    log_info(f"Target: {target_url}")
    log_info(f"Mode: {args.mode}")
    log_info(f"Threads: {threads}")
    
    # Show active integrations
    active_integrations = engine.get_integrations()
    if active_integrations:
        log_info(f"Integrations: {', '.join(active_integrations.keys())}")
    
    # Run scan
    if args.mode == "auto":
        result = engine.run_auto_scan(target_url)
    elif args.mode in CATEGORIES:
        result = engine.run_category_scan(target_url, args.mode)
    elif args.mode in MODULES:
        result = engine.run_module_scan(target_url, args.mode)
    else:
        result = engine.run_auto_scan(target_url)
    
    if "error" in result:
        log_error(f"Scan failed: {result['error']}")
        sys.exit(1)
    
    findings = result.get("findings", [])
    summary = result.get("summary", {})
    scan_id = result.get("scan_id", "unknown")
    
    # Learning mode: enhance findings with debug info
    if args.learn and findings:
        try:
            from debugger.vuln_debugger import VulnDebugger
            debugger = VulnDebugger()
            findings = debugger.debug_all(findings)
            log_info("Learning mode: Fix code and explanations added to findings")
        except Exception as e:
            log_warning(f"Learning mode error: {e}")
    
    # Display summary
    log_success(f"Scan complete — Score: {summary.get('security_score', 0)}/100")
    log_info(f"Total: {summary.get('total_findings', 0)} | "
             f"Critical: {summary.get('critical', 0)} | "
             f"High: {summary.get('high', 0)} | "
             f"Medium: {summary.get('medium', 0)} | "
             f"Low: {summary.get('low', 0)}")
    
    # Generate reports
    output_dir = args.output or None
    if args.report in ("html", "both"):
        try:
            from core.reporter import generate_html_report
            path = generate_html_report(scan_id, target_url, findings, summary)
            log_success(f"HTML report: {path}")
        except Exception as e:
            log_warning(f"HTML report error: {e}")
    
    if args.report in ("json", "both"):
        try:
            from core.reporter import generate_json_report
            path = generate_json_report(scan_id, target_url, findings, summary)
            log_success(f"JSON report: {path}")
        except Exception as e:
            log_warning(f"JSON report error: {e}")
    
    return 0 if summary.get('critical', 0) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
