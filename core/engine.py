"""Main scan orchestrator — auto mode, category mode, single module."""
# For authorized security testing only.
import uuid
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
from core.logger import log_info, log_success, log_error, log_warning, log_module
from core.target import Target
from core.database import create_scan, save_finding, update_scan_status, init_db
from core.reporter import generate_html_report, generate_json_report, calculate_security_score
from config import DEFAULT_THREADS, MIN_CONFIDENCE


class ScanEngine:
    def __init__(self, session_manager=None, threads: int = DEFAULT_THREADS, 
                 learning_mode: bool = False, callback=None):
        self.session_manager = session_manager
        self.threads = threads
        self.learning_mode = learning_mode
        self.callback = callback
        self.findings = []
        self.scan_id = None
        self._lock = threading.Lock()
        init_db()
    
    def _get_session(self):
        if self.session_manager:
            return self.session_manager.get_session()
        import requests
        import urllib3
        urllib3.disable_warnings()
        session = requests.Session()
        session.verify = False
        return session
    
    def add_finding(self, finding: Dict, scan_id: str = None):
        """Thread-safe finding addition."""
        with self._lock:
            if finding.get("confidence", 0) >= MIN_CONFIDENCE:
                self.findings.append(finding)
                sid = scan_id or self.scan_id
                if sid:
                    save_finding(sid, finding)
                if self.callback:
                    self.callback("finding", finding)
                log_info(f"Finding: [{finding.get('severity')}] {finding.get('vuln_type')} @ {finding.get('url')}")
    
    def run_auto_scan(self, target_url: str, config: Dict = None) -> Dict:
        """Run full automatic scan with all modules."""
        return self._run_scan(target_url, mode="auto", config=config or {})
    
    def run_category_scan(self, target_url: str, category: str, config: Dict = None) -> Dict:
        """Run scan for a specific category."""
        return self._run_scan(target_url, mode="category", category=category, config=config or {})
    
    def run_module_scan(self, target_url: str, module: str, config: Dict = None) -> Dict:
        """Run scan for a specific module."""
        return self._run_scan(target_url, mode="module", module=module, config=config or {})
    
    def _run_scan(self, target_url: str, mode: str = "auto", 
                  category: str = None, module: str = None, config: Dict = None) -> Dict:
        """Internal scan runner."""
        self.scan_id = str(uuid.uuid4())
        self.findings = []
        config = config or {}
        
        create_scan(self.scan_id, target_url, {
            "mode": mode, "category": category, "module": module, **config
        })
        
        if self.callback:
            self.callback("status", {"message": f"Starting {mode} scan...", "scan_id": self.scan_id})
        
        session = self._get_session()
        target = Target(target_url, session=session)
        
        if not target.check_availability():
            update_scan_status(self.scan_id, "failed")
            return {"error": "Target not available", "scan_id": self.scan_id}
        
        log_info("Phase 1: Reconnaissance")
        endpoints = self._run_recon(target, config)
        
        log_info("Phase 2: Exploitation")
        modules = self._get_modules(mode, category, module)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for mod_name, mod_func in modules:
                future = executor.submit(
                    self._run_module_safe, mod_name, mod_func, target, endpoints, config
                )
                futures.append(future)
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    log_error(f"Module error: {e}")
        
        score = calculate_security_score(self.findings)
        summary = {
            "total_findings": len(self.findings),
            "critical": sum(1 for f in self.findings if f.get("severity") == "Critical"),
            "high": sum(1 for f in self.findings if f.get("severity") == "High"),
            "medium": sum(1 for f in self.findings if f.get("severity") == "Medium"),
            "low": sum(1 for f in self.findings if f.get("severity") == "Low"),
            "security_score": score,
        }
        
        update_scan_status(self.scan_id, "completed", summary)
        
        if self.callback:
            self.callback("complete", {"summary": summary, "scan_id": self.scan_id})
        
        log_success(f"Scan complete. Found {len(self.findings)} vulnerabilities. Score: {score}/100")
        return {
            "scan_id": self.scan_id,
            "findings": self.findings,
            "summary": summary,
        }
    
    def _run_recon(self, target: Target, config: Dict) -> List[Dict]:
        """Run reconnaissance modules."""
        try:
            from recon.endpoint_discovery import EndpointDiscovery
            ed = EndpointDiscovery(target, target.session)
            endpoints = ed.discover()
            log_info(f"Discovered {len(endpoints)} endpoints")
            return endpoints
        except Exception as e:
            log_warning(f"Recon error: {e}")
            return [{"url": target.url, "method": "GET", "params": []}]
    
    def _run_module_safe(self, mod_name: str, mod_func, target: Target, 
                         endpoints: List[Dict], config: Dict):
        """Safely run a module."""
        try:
            log_module(mod_name)
            findings = mod_func(target, endpoints, target.session, config)
            if findings:
                for finding in findings:
                    self.add_finding(finding, self.scan_id)
        except Exception as e:
            log_error(f"Error in module {mod_name}: {e}")
    
    def _get_modules(self, mode: str, category: str = None, module: str = None) -> List:
        """Get list of modules to run based on mode."""
        all_modules = self._load_all_modules()
        if mode == "module" and module:
            return [(k, v) for k, v in all_modules.items() if k == module]
        elif mode == "category" and category:
            category_map = {
                "injection": ["sqli", "nosql", "cmd", "ssti", "xxe", "ldap", "xpath"],
                "client_side": ["xss", "csrf", "clickjack", "cors", "open_redirect", "prototype_pollution"],
                "server_side": ["ssrf", "lfi", "rfi", "file_upload", "rce", "http_smuggling"],
                "auth": ["auth_bypass", "jwt", "session", "oauth", "idor", "account_takeover"],
                "logic": ["race_condition", "business_logic", "mass_assignment", "rate_limit"],
                "advanced": ["graphql", "websocket", "cache_poison", "crlf", "host_header", "subdomain_takeover"],
            }
            allowed = category_map.get(category, [])
            return [(k, v) for k, v in all_modules.items() if k in allowed]
        else:
            return list(all_modules.items())
    
    def _load_all_modules(self) -> Dict:
        """Dynamically load all exploit modules."""
        modules = {}
        module_paths = [
            ("sqli", "exploits.injection.sqli_exploiter", "SQLiExploiter"),
            ("nosql", "exploits.injection.nosql_exploiter", "NoSQLExploiter"),
            ("cmd", "exploits.injection.cmd_exploiter", "CMDExploiter"),
            ("ssti", "exploits.injection.ssti_exploiter", "SSTIExploiter"),
            ("xxe", "exploits.injection.xxe_exploiter", "XXEExploiter"),
            ("ldap", "exploits.injection.ldap_exploiter", "LDAPExploiter"),
            ("xpath", "exploits.injection.xpath_exploiter", "XPathExploiter"),
            ("xss", "exploits.client_side.xss_exploiter", "XSSExploiter"),
            ("csrf", "exploits.client_side.csrf_exploiter", "CSRFExploiter"),
            ("clickjack", "exploits.client_side.clickjack_exploiter", "ClickjackExploiter"),
            ("cors", "exploits.client_side.cors_exploiter", "CORSExploiter"),
            ("open_redirect", "exploits.client_side.open_redirect_exploiter", "OpenRedirectExploiter"),
            ("prototype_pollution", "exploits.client_side.prototype_pollution_exploiter", "PrototypePollutionExploiter"),
            ("ssrf", "exploits.server_side.ssrf_exploiter", "SSRFExploiter"),
            ("lfi", "exploits.server_side.lfi_exploiter", "LFIExploiter"),
            ("rfi", "exploits.server_side.rfi_exploiter", "RFIExploiter"),
            ("file_upload", "exploits.server_side.file_upload_exploiter", "FileUploadExploiter"),
            ("rce", "exploits.server_side.rce_exploiter", "RCEExploiter"),
            ("http_smuggling", "exploits.server_side.http_smuggling_exploiter", "HTTPSmugglingExploiter"),
            ("auth_bypass", "exploits.auth.auth_bypass_exploiter", "AuthBypassExploiter"),
            ("jwt", "exploits.auth.jwt_exploiter", "JWTExploiter"),
            ("session", "exploits.auth.session_exploiter", "SessionExploiter"),
            ("oauth", "exploits.auth.oauth_exploiter", "OAuthExploiter"),
            ("idor", "exploits.auth.idor_exploiter", "IDORExploiter"),
            ("account_takeover", "exploits.auth.account_takeover_exploiter", "AccountTakeoverExploiter"),
            ("race_condition", "exploits.logic.race_condition_exploiter", "RaceConditionExploiter"),
            ("business_logic", "exploits.logic.business_logic_exploiter", "BusinessLogicExploiter"),
            ("mass_assignment", "exploits.logic.mass_assignment_exploiter", "MassAssignmentExploiter"),
            ("rate_limit", "exploits.logic.rate_limit_exploiter", "RateLimitExploiter"),
            ("graphql", "exploits.advanced.graphql_exploiter", "GraphQLExploiter"),
            ("websocket", "exploits.advanced.websocket_exploiter", "WebSocketExploiter"),
            ("cache_poison", "exploits.advanced.cache_poison_exploiter", "CachePoisonExploiter"),
            ("crlf", "exploits.advanced.crlf_exploiter", "CRLFExploiter"),
            ("host_header", "exploits.advanced.host_header_exploiter", "HostHeaderExploiter"),
            ("subdomain_takeover", "exploits.advanced.subdomain_takeover_exploiter", "SubdomainTakeoverExploiter"),
        ]
        for mod_name, mod_path, class_name in module_paths:
            try:
                import importlib
                mod = importlib.import_module(mod_path)
                cls = getattr(mod, class_name)
                def make_runner(c):
                    def runner(target, endpoints, session, config):
                        exploiter = c(session=session)
                        return exploiter.run(target, endpoints)
                    return runner
                modules[mod_name] = make_runner(cls)
            except Exception as e:
                log_warning(f"Could not load module {mod_name}: {e}")
        return modules
