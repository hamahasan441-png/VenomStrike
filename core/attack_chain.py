"""Attack Chain Correlator — multi-stage vulnerability path detection.

Hydra Edition (v8.0) introduces attack chain correlation that identifies
how individual vulnerabilities can be chained together to form realistic,
multi-stage attack paths.  This transforms isolated findings into
actionable attack narratives that demonstrate real-world impact.

For example:
- SSRF → Internal Service Access → RCE
- XSS → Session Hijacking → Account Takeover
- SQLi → Data Exfiltration → Privilege Escalation
- IDOR → Data Leak → Account Takeover

For authorized security testing only.
"""
import logging
from typing import Dict, List, Optional

logger = logging.getLogger("venomstrike.attack_chain")


class AttackChain:
    """Represents a multi-stage attack chain linking related findings."""

    __slots__ = ("chain_id", "stages", "total_severity", "description",
                 "impact_rating", "attack_narrative")

    def __init__(self, chain_id: str):
        self.chain_id = chain_id
        self.stages: List[Dict] = []
        self.total_severity = ""
        self.description = ""
        self.impact_rating = 0
        self.attack_narrative = ""

    def add_stage(self, finding: Dict, stage_number: int, role: str) -> None:
        """Add a finding as a stage in the attack chain.

        Args:
            finding: The vulnerability finding dict.
            stage_number: The position in the chain (1-based).
            role: The role this finding plays (e.g. "entry_point",
                "pivot", "escalation", "exfiltration").
        """
        self.stages.append({
            "stage": stage_number,
            "role": role,
            "vuln_type": finding.get("vuln_type", ""),
            "url": finding.get("url", ""),
            "param": finding.get("param", ""),
            "severity": finding.get("severity", ""),
            "confidence": finding.get("confidence", 0),
            "finding_fingerprint": finding.get("fingerprint", ""),
        })

    def to_dict(self) -> Dict:
        return {
            "chain_id": self.chain_id,
            "stages": self.stages,
            "stage_count": len(self.stages),
            "total_severity": self.total_severity,
            "description": self.description,
            "impact_rating": self.impact_rating,
            "attack_narrative": self.attack_narrative,
        }


class AttackChainCorrelator:
    """Detect and build multi-stage attack chains from findings.

    The correlator examines all findings from a scan and identifies
    combinations that could form realistic attack paths.  It uses a
    rule-based engine that understands common vulnerability chain
    patterns observed in real-world penetration tests.

    Usage::

        correlator = AttackChainCorrelator()
        chains = correlator.correlate(findings)
        for chain in chains:
            print(chain.description, chain.impact_rating)
    """

    # Chain rules: (entry_vuln, pivot_vuln, ...) → chain template
    CHAIN_RULES: List[Dict] = [
        {
            "name": "SSRF to Internal RCE",
            "pattern": ["ssrf", "rce"],
            "description": "SSRF provides access to internal services, enabling remote code execution",
            "impact": 10,
            "narrative": (
                "An attacker exploits the SSRF vulnerability to reach internal services "
                "that are not exposed to the internet. Through the internal service, "
                "the attacker achieves remote code execution on the server."
            ),
        },
        {
            "name": "SQLi to Data Exfiltration",
            "pattern": ["sqli"],
            "min_confidence": 80,
            "description": "SQL injection enables database exfiltration and potential privilege escalation",
            "impact": 9,
            "narrative": (
                "An attacker exploits SQL injection to extract sensitive data from the "
                "database, including credentials, personal data, and application secrets. "
                "Extracted credentials may enable further system access."
            ),
        },
        {
            "name": "XSS to Account Takeover",
            "pattern": ["xss", "session"],
            "description": "XSS enables session hijacking leading to account takeover",
            "impact": 9,
            "narrative": (
                "An attacker injects malicious JavaScript via the XSS vulnerability to "
                "steal session tokens. Using the hijacked session, the attacker gains "
                "full access to the victim's account."
            ),
        },
        {
            "name": "XSS to CSRF Chain",
            "pattern": ["xss", "csrf"],
            "description": "XSS bypasses CSRF protections enabling unauthorized actions",
            "impact": 8,
            "narrative": (
                "An attacker uses XSS to bypass CSRF token validation and execute "
                "unauthorized state-changing actions on behalf of authenticated users."
            ),
        },
        {
            "name": "IDOR to Data Breach",
            "pattern": ["idor"],
            "min_confidence": 80,
            "description": "IDOR enables unauthorized access to other users' data",
            "impact": 8,
            "narrative": (
                "An attacker manipulates object identifiers to access resources belonging "
                "to other users, potentially exfiltrating sensitive personal data at scale."
            ),
        },
        {
            "name": "Auth Bypass to Full Compromise",
            "pattern": ["auth_bypass", "sqli"],
            "description": "Authentication bypass combined with injection enables full system compromise",
            "impact": 10,
            "narrative": (
                "An attacker bypasses authentication controls to gain unauthorized access, "
                "then exploits SQL injection in authenticated endpoints to exfiltrate data "
                "and potentially execute commands on the server."
            ),
        },
        {
            "name": "LFI to RCE via Log Poisoning",
            "pattern": ["lfi", "rce"],
            "description": "Local file inclusion enables log poisoning leading to code execution",
            "impact": 10,
            "narrative": (
                "An attacker uses LFI to read server log files, then poisons the logs "
                "with injected code. Re-including the poisoned log file via LFI achieves "
                "remote code execution."
            ),
        },
        {
            "name": "JWT Weakness to Privilege Escalation",
            "pattern": ["jwt", "idor"],
            "description": "JWT vulnerability enables token forgery leading to privilege escalation",
            "impact": 9,
            "narrative": (
                "An attacker exploits a JWT weakness (algorithm confusion or weak secret) "
                "to forge tokens with elevated privileges, then accesses other users' "
                "resources through IDOR-vulnerable endpoints."
            ),
        },
        {
            "name": "CORS to Data Theft",
            "pattern": ["cors"],
            "min_confidence": 80,
            "description": "CORS misconfiguration enables cross-origin data theft",
            "impact": 7,
            "narrative": (
                "An attacker hosts a malicious page that exploits the CORS misconfiguration "
                "to make cross-origin requests and steal authenticated user data from the "
                "vulnerable application's API endpoints."
            ),
        },
        {
            "name": "Open Redirect to Phishing",
            "pattern": ["open_redirect"],
            "min_confidence": 70,
            "description": "Open redirect enables credential phishing via trusted domain",
            "impact": 6,
            "narrative": (
                "An attacker crafts a URL using the trusted domain that redirects victims "
                "to a phishing page. The trusted domain in the URL increases the success "
                "rate of the phishing attack."
            ),
        },
        {
            "name": "SSTI to RCE",
            "pattern": ["ssti"],
            "min_confidence": 80,
            "description": "Server-side template injection enables direct code execution",
            "impact": 10,
            "narrative": (
                "An attacker exploits template injection to escape the template sandbox "
                "and execute arbitrary code on the server, gaining full system access."
            ),
        },
        {
            "name": "XXE to Internal Network Scan",
            "pattern": ["xxe", "ssrf"],
            "description": "XXE enables internal network scanning and data exfiltration",
            "impact": 9,
            "narrative": (
                "An attacker exploits XXE to make the server issue requests to internal "
                "network addresses, mapping internal infrastructure and accessing "
                "sensitive internal services."
            ),
        },
        {
            "name": "Race Condition to Business Logic Abuse",
            "pattern": ["race_condition", "business_logic"],
            "description": "Race condition enables business logic abuse for financial gain",
            "impact": 8,
            "narrative": (
                "An attacker exploits a race condition to perform duplicate transactions "
                "or bypass rate limits, then chains this with business logic flaws for "
                "unauthorized financial benefit."
            ),
        },
        {
            "name": "Command Injection to Full Compromise",
            "pattern": ["cmd"],
            "min_confidence": 80,
            "description": "OS command injection provides direct server access",
            "impact": 10,
            "narrative": (
                "An attacker exploits command injection to execute arbitrary OS commands, "
                "establishing a persistent backdoor, exfiltrating data, and potentially "
                "pivoting to other systems on the network."
            ),
        },
    ]

    # Severity escalation rules
    SEVERITY_ESCALATION = {
        10: "Critical",
        9: "Critical",
        8: "High",
        7: "High",
        6: "Medium",
        5: "Medium",
    }

    def correlate(self, findings: List[Dict], max_chains: int = 20) -> List[AttackChain]:
        """Detect attack chains from a list of findings.

        Args:
            findings: List of finding dicts from the scan.
            max_chains: Maximum number of chains to return.

        Returns:
            List of AttackChain objects, sorted by impact rating.
        """
        if not findings:
            return []

        # Index findings by vuln_type
        by_type: Dict[str, List[Dict]] = {}
        for f in findings:
            vtype = f.get("vuln_type", "").lower()
            # Normalize vuln type to base category
            base = self._normalize_vuln_type(vtype)
            by_type.setdefault(base, []).append(f)

        chains: List[AttackChain] = []
        chain_counter = 0

        for rule in self.CHAIN_RULES:
            pattern = rule["pattern"]
            min_conf = rule.get("min_confidence", 0)

            # Check if all required vuln types are present
            if len(pattern) == 1:
                # Single-vuln chain — requires high confidence
                base_type = pattern[0]
                if base_type in by_type:
                    matching = [
                        f for f in by_type[base_type]
                        if f.get("confidence", 0) >= min_conf
                    ]
                    if matching:
                        chain_counter += 1
                        chain = AttackChain(f"chain_{chain_counter}")
                        chain.description = rule["description"]
                        chain.attack_narrative = rule["narrative"]
                        chain.impact_rating = rule["impact"]
                        chain.total_severity = self.SEVERITY_ESCALATION.get(
                            rule["impact"], "High"
                        )
                        # Use the highest-confidence finding
                        best = max(matching, key=lambda x: x.get("confidence", 0))
                        chain.add_stage(best, 1, "entry_point")
                        chains.append(chain)
            else:
                # Multi-vuln chain
                all_present = all(p in by_type for p in pattern)
                if all_present:
                    chain_counter += 1
                    chain = AttackChain(f"chain_{chain_counter}")
                    chain.description = rule["description"]
                    chain.attack_narrative = rule["narrative"]
                    chain.impact_rating = rule["impact"]
                    chain.total_severity = self.SEVERITY_ESCALATION.get(
                        rule["impact"], "High"
                    )
                    for idx, vuln_t in enumerate(pattern):
                        role = "entry_point" if idx == 0 else (
                            "escalation" if idx == len(pattern) - 1 else "pivot"
                        )
                        best = max(
                            by_type[vuln_t],
                            key=lambda x: x.get("confidence", 0),
                        )
                        chain.add_stage(best, idx + 1, role)
                    chains.append(chain)

        # Sort by impact rating descending
        chains.sort(key=lambda c: c.impact_rating, reverse=True)
        return chains[:max_chains]

    def enrich_findings_with_chains(
        self, findings: List[Dict], chains: List["AttackChain"],
    ) -> List[Dict]:
        """Add attack chain references to findings.

        Each finding that participates in a chain gets an ``attack_chains``
        field listing the chains it belongs to.
        """
        # Build a map from fingerprint → chain info
        fp_chains: Dict[str, List[Dict]] = {}
        for chain in chains:
            for stage in chain.stages:
                fp = stage.get("finding_fingerprint", "")
                if fp:
                    fp_chains.setdefault(fp, []).append({
                        "chain_id": chain.chain_id,
                        "chain_description": chain.description,
                        "impact_rating": chain.impact_rating,
                        "stage": stage["stage"],
                        "role": stage["role"],
                    })

        for finding in findings:
            fp = finding.get("fingerprint", "")
            if fp in fp_chains:
                finding["attack_chains"] = fp_chains[fp]
                # Boost confidence for findings in high-impact chains
                max_impact = max(c["impact_rating"] for c in fp_chains[fp])
                if max_impact >= 9:
                    finding["confidence"] = min(
                        100, finding.get("confidence", 0) + 10
                    )
                elif max_impact >= 7:
                    finding["confidence"] = min(
                        100, finding.get("confidence", 0) + 5
                    )

        return findings

    @staticmethod
    def _normalize_vuln_type(vuln_type: str) -> str:
        """Normalize a specific vuln type to its base category."""
        vt = vuln_type.lower().replace("-", "_").replace(" ", "_")

        # Handle prefixed types (e.g. "nuclei:xxx")
        if ":" in vt:
            vt = vt.split(":", 1)[1]

        # Normalize aliases
        aliases = {
            "sql_injection": "sqli",
            "nosql_injection": "nosql",
            "command_injection": "cmd",
            "xss_reflected": "xss",
            "xss_stored": "xss",
            "xss_dom": "xss",
            "cross_site_scripting": "xss",
            "server_side_request_forgery": "ssrf",
            "local_file_inclusion": "lfi",
            "remote_file_inclusion": "rfi",
            "remote_code_execution": "rce",
            "template_injection": "ssti",
        }
        return aliases.get(vt, vt)
