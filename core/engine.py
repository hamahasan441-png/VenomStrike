"""Main scan orchestrator — auto mode, category mode, single module, tool integrations."""
# For authorized security testing only.
import uuid
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from typing import List, Dict, Optional
from core.logger import log_info, log_success, log_error, log_warning, log_module
from core.target import Target
from core.database import create_scan, save_finding, update_scan_status, init_db
from core.reporter import generate_html_report, generate_json_report, calculate_security_score
from config import (
    DEFAULT_THREADS, MIN_CONFIDENCE, CVE_ENRICH_LIMIT, MODULE_TIMEOUT,
    SCAN_DEPTH, DEPTH_PRESETS,
    NMAP_ENABLED, NMAP_PATH,
    SHODAN_API_KEY,
    ZAP_ENABLED, ZAP_API_KEY, ZAP_PROXY,
    NUCLEI_ENABLED, NUCLEI_PATH, NUCLEI_TEMPLATES_DIR,
    NVD_API_KEY,
)


class ScanEngine:
    def __init__(self, session_manager=None, threads: int = DEFAULT_THREADS, 
                 learning_mode: bool = False, callback=None,
                 enable_integrations: bool = True, depth: str = None):
        self.session_manager = session_manager
        self.threads = threads
        self.learning_mode = learning_mode
        self.callback = callback
        self.enable_integrations = enable_integrations
        self.depth = depth or SCAN_DEPTH
        self.depth_preset = DEPTH_PRESETS.get(self.depth, DEPTH_PRESETS["standard"])
        self.findings = []
        self.scan_id = None
        self._lock = threading.Lock()
        self._integrations = {}
        self._cancelled = False
        init_db()
        if enable_integrations:
            self._init_integrations()

    # ── Graceful shutdown ──────────────────────────────────────────
    def cancel(self):
        """Signal the engine to stop processing new modules."""
        self._cancelled = True
        log_warning("Scan cancellation requested — finishing current modules…")
    
    def _init_integrations(self):
        """Initialize available tool integrations."""
        if NMAP_ENABLED:
            try:
                from integrations.nmap_scanner import NmapScanner
                scanner = NmapScanner(nmap_path=NMAP_PATH)
                if scanner.is_available():
                    self._integrations["nmap"] = scanner
                    log_info("Integration: Nmap enabled")
            except Exception as e:
                log_warning(f"Nmap integration error: {e}")

        if SHODAN_API_KEY:
            try:
                from integrations.shodan_recon import ShodanRecon
                recon = ShodanRecon(api_key=SHODAN_API_KEY)
                if recon.is_available():
                    self._integrations["shodan"] = recon
                    log_info("Integration: Shodan enabled")
            except Exception as e:
                log_warning(f"Shodan integration error: {e}")

        if ZAP_ENABLED:
            try:
                from integrations.zap_scanner import ZAPScanner
                zap = ZAPScanner(api_key=ZAP_API_KEY, proxy=ZAP_PROXY)
                if zap.is_available():
                    self._integrations["zap"] = zap
                    log_info("Integration: OWASP ZAP enabled")
            except Exception as e:
                log_warning(f"ZAP integration error: {e}")

        if NUCLEI_ENABLED:
            try:
                from integrations.nuclei_runner import NucleiRunner
                nuclei = NucleiRunner(nuclei_path=NUCLEI_PATH, templates_dir=NUCLEI_TEMPLATES_DIR)
                if nuclei.is_available():
                    self._integrations["nuclei"] = nuclei
                    log_info("Integration: Nuclei enabled")
            except Exception as e:
                log_warning(f"Nuclei integration error: {e}")

        if NVD_API_KEY:
            try:
                from integrations.cve_lookup import CVELookup
                self._integrations["cve"] = CVELookup(api_key=NVD_API_KEY)
                log_info("Integration: NVD/CVE lookup enabled")
            except Exception as e:
                log_warning(f"CVE lookup integration error: {e}")

    def get_integrations(self) -> Dict:
        """Return available integrations for status display."""
        return {name: True for name in self._integrations}

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
            self.callback("status", {"message": f"Starting {mode} scan (depth={self.depth})...", "scan_id": self.scan_id})
        
        session = self._get_session()
        target = Target(target_url, session=session)
        
        if not target.check_availability():
            update_scan_status(self.scan_id, "failed")
            return {"error": "Target not available", "scan_id": self.scan_id}
        
        log_info("Phase 1: Reconnaissance")
        endpoints = self._run_recon(target, config)
        
        # Phase 1.5: Run tool integrations for additional recon
        if self._integrations:
            log_info("Phase 1.5: Tool Integrations")
            self._run_integrations(target, config)
        
        log_info("Phase 2: Exploitation")
        modules = self._get_modules(mode, category, module)

        # Phase 1.8: Parameter Deduplication (v10.0 Phoenix)
        if self.depth_preset.get("param_deduplication"):
            log_info("Phase 1.8: Smart Parameter Deduplication")
            try:
                from core.param_deduplicator import SmartParamDeduplicator
                deduplicator = SmartParamDeduplicator()
                endpoints = deduplicator.deduplicate_endpoints(endpoints)
                stats = deduplicator.get_stats()
                if stats["reduction_percent"] > 0:
                    log_info(
                        f"Parameter dedup: {stats['total_before']} → "
                        f"{stats['total_after']} params "
                        f"({stats['reduction_percent']}% reduction)"
                    )
            except Exception as e:
                log_warning(f"Parameter deduplication error: {e}")
        
        module_timeout = MODULE_TIMEOUT if MODULE_TIMEOUT > 0 else None
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for mod_name, mod_func in modules:
                if self._cancelled:
                    break
                future = executor.submit(
                    self._run_module_safe, mod_name, mod_func, target, endpoints, config
                )
                futures[future] = mod_name
            for future in as_completed(futures, timeout=module_timeout):
                if self._cancelled:
                    break
                mod_name = futures[future]
                try:
                    future.result(timeout=0)
                except FuturesTimeoutError:
                    log_warning(f"Module {mod_name} timed out after {module_timeout}s")
                except Exception as e:
                    log_error(f"Module {mod_name} error: {e}")
        
        # Phase 3: Verification — deduplicate and verify findings
        log_info("Phase 3: Verification & Deduplication")
        self.findings = self._verify_and_deduplicate(self.findings)
        
        # Phase 3b: Quantum cross-correlation (v4.0)
        if self.depth_preset.get("cross_correlation"):
            log_info("Phase 3b: Quantum Cross-Correlation Analysis")
            try:
                from core.validator import ResultValidator
                validator = ResultValidator(session=self.session_manager.session if self.session_manager else None)
                self.findings = validator.cross_correlate_findings(self.findings)
            except Exception as e:
                log_warning(f"Cross-correlation error: {e}")

        # Phase 3c: OOB Verification (v7.0 Titan)
        if self.depth_preset.get("oob_verification"):
            log_info("Phase 3c: Out-of-Band Verification")
            try:
                from core.oob_verifier import OOBVerifier
                oob = OOBVerifier()
                if oob.is_configured:
                    for token in oob.get_pending_tokens():
                        result = oob.check_callback(token)
                        if result.get("verified"):
                            log_success(
                                f"OOB confirmed: {token.vuln_type} @ "
                                f"{token.url} param={token.param}"
                            )
                else:
                    log_info("OOB verification: no callback domain configured (dry-run)")
            except Exception as e:
                log_warning(f"OOB verification error: {e}")

        # Phase 3d: Bayesian Confidence Scoring (v8.0 Hydra)
        if self.depth_preset.get("bayesian_scoring"):
            log_info("Phase 3d: Bayesian Confidence Scoring")
            try:
                from core.bayesian_scorer import BayesianConfidenceScorer
                scorer = BayesianConfidenceScorer()
                for finding in self.findings:
                    signals = self._extract_evidence_signals(finding)
                    if signals:
                        result = scorer.combine_with_existing(
                            finding.get("confidence", 50), signals
                        )
                        finding["confidence"] = result["confidence"]
                        finding["bayesian_posterior"] = result["posterior"]
                        finding["bayesian_signals"] = result["signals_used"]
            except Exception as e:
                log_warning(f"Bayesian scoring error: {e}")

        # Phase 3e: Attack Chain Correlation (v8.0 Hydra)
        if self.depth_preset.get("attack_chain_correlation"):
            log_info("Phase 3e: Attack Chain Correlation")
            try:
                from core.attack_chain import AttackChainCorrelator
                correlator = AttackChainCorrelator()
                chains = correlator.correlate(self.findings)
                if chains:
                    self.findings = correlator.enrich_findings_with_chains(
                        self.findings, chains
                    )
                    log_info(f"Detected {len(chains)} attack chain(s)")
                    for chain in chains:
                        log_info(
                            f"  Chain: {chain.description} "
                            f"(impact: {chain.impact_rating}/10, "
                            f"stages: {len(chain.stages)})"
                        )
            except Exception as e:
                log_warning(f"Attack chain correlation error: {e}")

        # Phase 3f: Vulnerability Correlation (v9.0 Chimera)
        if self.depth_preset.get("vulnerability_correlation"):
            log_info("Phase 3f: Cross-Module Vulnerability Correlation")
            try:
                from core.vulnerability_correlator import VulnerabilityCorrelator
                vuln_correlator = VulnerabilityCorrelator()
                correlation_result = vuln_correlator.correlate(self.findings)
                compounds = correlation_result.get("compound_vulnerabilities", [])
                systemic = correlation_result.get("systemic_weaknesses", [])
                if compounds:
                    log_info(f"Detected {len(compounds)} compound vulnerability/ies")
                if systemic:
                    log_warning(f"Detected {len(systemic)} systemic weakness(es)")
                # Store correlation data for reporting
                self._correlation_result = correlation_result
            except Exception as e:
                log_warning(f"Vulnerability correlation error: {e}")

        # Phase 3g: Context-Aware Validation (v10.0 Phoenix)
        if self.depth_preset.get("context_validation"):
            log_info("Phase 3g: Context-Aware Vulnerability Validation")
            try:
                from core.context_validator import ContextValidator
                ctx_validator = ContextValidator()
                self.findings = ctx_validator.validate_findings(self.findings)
                stats = ctx_validator.get_stats()
                if stats["rejected_as_fp"] > 0:
                    log_info(
                        f"Context validation: {stats['rejected_as_fp']} "
                        f"finding(s) flagged as technology-specific FP"
                    )
            except Exception as e:
                log_warning(f"Context validation error: {e}")

        # Phase 3h: Impact Analysis (v10.0 Phoenix)
        if self.depth_preset.get("impact_analysis"):
            log_info("Phase 3h: Vulnerability Impact Analysis")
            try:
                from core.impact_analyzer import ImpactAnalyzer
                analyzer = ImpactAnalyzer()
                self.findings = analyzer.analyze_findings(self.findings)
                log_info(
                    f"Impact analysis: {analyzer.analyzed_count} "
                    f"finding(s) analysed and prioritised"
                )
            except Exception as e:
                log_warning(f"Impact analysis error: {e}")

        # Phase 4: CVE Enrichment
        if self._integrations.get("cve"):
            log_info("Phase 4: CVE Enrichment")
            self.findings = self._enrich_findings_with_cves(self.findings)
        
        score = calculate_security_score(self.findings)
        
        # Count by verification status
        verified_count = sum(
            1 for f in self.findings
            if f.get("verification_status") in ("confirmed", "likely")
        )
        suspicious_count = sum(
            1 for f in self.findings
            if f.get("verification_status") == "suspicious"
        )
        
        summary = {
            "total_findings": len(self.findings),
            "verified_findings": verified_count,
            "suspicious_findings": suspicious_count,
            "critical": sum(1 for f in self.findings if f.get("severity") == "Critical"),
            "high": sum(1 for f in self.findings if f.get("severity") == "High"),
            "medium": sum(1 for f in self.findings if f.get("severity") == "Medium"),
            "low": sum(1 for f in self.findings if f.get("severity") == "Low"),
            "security_score": score,
        }
        
        update_scan_status(self.scan_id, "completed", summary)
        
        if self.callback:
            self.callback("complete", {"summary": summary, "scan_id": self.scan_id})
        
        log_success(
            f"Scan complete. {len(self.findings)} findings "
            f"({verified_count} verified, {suspicious_count} suspicious). "
            f"Score: {score}/100"
        )
        return {
            "scan_id": self.scan_id,
            "findings": self.findings,
            "summary": summary,
        }
    
    def _run_recon(self, target: Target, config: Dict) -> List[Dict]:
        """Run reconnaissance modules."""
        try:
            from recon.endpoint_discovery import EndpointDiscovery
            ed = EndpointDiscovery(target, target.session, depth_preset=self.depth_preset)
            endpoints = ed.discover()
            log_info(f"Discovered {len(endpoints)} endpoints")
            return endpoints
        except Exception as e:
            log_warning(f"Recon error: {e}")
            return [{"url": target.url, "method": "GET", "params": []}]

    def _run_integrations(self, target: Target, config: Dict):
        """Run external tool integrations for additional intelligence."""
        import urllib.parse
        hostname = urllib.parse.urlparse(target.url).hostname or ""

        # Nmap port scan
        if "nmap" in self._integrations:
            try:
                nmap = self._integrations["nmap"]
                results = nmap.quick_scan(hostname)
                if results.get("open_ports"):
                    log_info(f"Nmap: {len(results['open_ports'])} open ports found")
                    for svc in results.get("services", []):
                        log_info(f"  Service: {svc}")
            except Exception as e:
                log_warning(f"Nmap integration: {e}")

        # Shodan passive recon
        if "shodan" in self._integrations:
            try:
                import socket
                ip = socket.gethostbyname(hostname)
                shodan = self._integrations["shodan"]
                host_data = shodan.host_lookup(ip)
                if host_data:
                    vulns = host_data.get("vulns", [])
                    if vulns:
                        log_warning(f"Shodan: {len(vulns)} known vulnerabilities for {ip}")
                    log_info(f"Shodan: {len(host_data.get('ports', []))} ports, "
                             f"OS: {host_data.get('os', 'unknown')}")
            except Exception as e:
                log_warning(f"Shodan integration: {e}")

        # Nuclei scan
        if "nuclei" in self._integrations:
            try:
                nuclei = self._integrations["nuclei"]
                results = nuclei.scan(target.url, severity="critical,high,medium")
                for r in results:
                    finding = {
                        "vuln_type": f"nuclei:{r.get('template_id', 'unknown')}",
                        "url": r.get("matched_at", target.url),
                        "param": "",
                        "payload": "",
                        "severity": r.get("severity", "Info"),
                        "confidence": 90,
                        "evidence": {"source": "nuclei", "description": r.get("description", "")},
                        "cwe": "",
                        "cvss": 0.0,
                        "owasp": "",
                        "timestamp": time.time(),
                    }
                    self.add_finding(finding, self.scan_id)
                if results:
                    log_info(f"Nuclei: {len(results)} findings")
            except Exception as e:
                log_warning(f"Nuclei integration: {e}")

        # ZAP spider + scan
        if "zap" in self._integrations:
            try:
                zap = self._integrations["zap"]
                spider_result = zap.spider(target.url)
                log_info(f"ZAP Spider: {spider_result.get('urls_found', 0)} URLs discovered")
            except Exception as e:
                log_warning(f"ZAP integration: {e}")

    def _enrich_findings_with_cves(self, findings: List[Dict]) -> List[Dict]:
        """Enrich findings with CVE data from NVD."""
        if "cve" not in self._integrations:
            return findings
        cve_lookup = self._integrations["cve"]
        for finding in findings[:CVE_ENRICH_LIMIT]:
            try:
                cve_lookup.enrich_finding(finding)
            except Exception:
                pass
        return findings

    def _verify_and_deduplicate(self, findings: List[Dict]) -> List[Dict]:
        """Deduplicate findings and tag verification status.

        Dedup key: vuln_type + url + param (same as EvidencePackage fingerprint).
        For duplicates, keep the finding with higher confidence.
        Findings without verification_status get tagged as 'unverified'.
        """
        import hashlib
        seen = {}
        for finding in findings:
            # Compute dedup key
            fp = finding.get("fingerprint", "")
            if not fp:
                raw = (
                    f"{finding.get('vuln_type', '')}|"
                    f"{finding.get('url', '')}|"
                    f"{finding.get('param', '')}"
                )
                fp = hashlib.sha256(raw.encode()).hexdigest()[:16]
                finding["fingerprint"] = fp

            # Ensure verification_status exists
            if "verification_status" not in finding:
                finding["verification_status"] = "unverified"
                finding["verification_details"] = "Not yet validated"

            # Ensure proof_description exists
            if "proof_description" not in finding:
                evidence = finding.get("evidence", {})
                if isinstance(evidence, dict):
                    finding["proof_description"] = evidence.get(
                        "proof_description",
                        evidence.get("verification_details", "No proof collected")
                    )
                else:
                    finding["proof_description"] = "No proof collected"

            # Keep highest confidence per fingerprint
            if fp in seen:
                if finding.get("confidence", 0) > seen[fp].get("confidence", 0):
                    seen[fp] = finding
            else:
                seen[fp] = finding

        deduped = list(seen.values())
        removed = len(findings) - len(deduped)
        if removed > 0:
            log_info(f"Deduplication: removed {removed} duplicate findings")
        return deduped

    @staticmethod
    def _extract_evidence_signals(finding: Dict) -> Dict:
        """Extract Bayesian evidence signals from a finding for scoring.

        Examines the evidence package, verification status, and proof data
        to build a signal dict suitable for BayesianConfidenceScorer.
        """
        signals = {}
        evidence = finding.get("evidence", {})
        if not isinstance(evidence, dict):
            return signals

        proof = evidence.get("proof_data", {})

        # Map proof data keys to Bayesian signals
        if proof.get("error_pattern"):
            signals["error_pattern"] = True
        if proof.get("reflected_payload") or proof.get("reflected_part"):
            signals["payload_reflected"] = True
        if proof.get("timing_diff"):
            signals["timing_confirmed"] = True
        if proof.get("response_diff_percent"):
            signals["response_diff"] = True
        if proof.get("baseline_missing_pattern"):
            signals["baseline_clean"] = True
        if proof.get("content_match") or proof.get("file_content_indicator"):
            signals["content_match"] = True
        if proof.get("entropy_delta"):
            signals["entropy_anomaly"] = True
        if proof.get("cross_correlated"):
            signals["cross_correlated"] = True
        if proof.get("oob_verified"):
            signals["oob_verified"] = True
        if proof.get("triple_confirmation"):
            signals["triple_confirmed"] = True

        # Retest status
        v_status = finding.get("verification_status", "")
        if v_status == "confirmed":
            signals["retest_confirmed"] = True
        elif v_status in ("suspicious", "unverified"):
            signals["retest_confirmed"] = False

        # Attack chain correlation
        if finding.get("attack_chains"):
            signals["chain_correlated"] = True

        return signals
    
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
                "advanced": ["graphql", "websocket", "cache_poison", "crlf", "host_header", "subdomain_takeover",
                             "deserialization", "api_key_exposure", "http2_desync", "parameter_tampering"],
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
            ("deserialization", "exploits.advanced.deserialization_exploiter", "DeserializationExploiter"),
            ("api_key_exposure", "exploits.advanced.api_key_exposure_exploiter", "APIKeyExposureExploiter"),
            ("http2_desync", "exploits.advanced.http2_desync_exploiter", "HTTP2DesyncExploiter"),
            ("parameter_tampering", "exploits.advanced.parameter_tampering_exploiter", "ParameterTamperingExploiter"),
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
