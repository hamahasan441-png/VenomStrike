"""SARIF Reporter — Static Analysis Results Interchange Format output.

Chimera Edition (v9.0) introduces SARIF output for seamless CI/CD pipeline
integration.  SARIF is the standard format consumed by GitHub Code Scanning,
Azure DevOps, and other security-aware CI platforms.

Key capabilities:
- **SARIF v2.1.0 compliant**: Full compliance with the OASIS standard.
- **CWE mapping**: Maps VenomStrike vulnerability types to CWE identifiers.
- **Severity mapping**: Maps VenomStrike severity levels to SARIF levels.
- **Rich descriptions**: Includes detailed vulnerability descriptions,
  remediation guidance, and evidence in SARIF message fields.
- **Tool metadata**: Proper VenomStrike tool identification and version.

For authorized security testing only.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from config import CODENAME, TOOL_NAME, VERSION

logger = logging.getLogger("venomstrike.sarif_reporter")

# VenomStrike vuln_type → CWE mapping
VULN_TYPE_CWE_MAP: Dict[str, Dict] = {
    "sqli": {"id": "CWE-89", "name": "SQL Injection"},
    "xss": {"id": "CWE-79", "name": "Cross-site Scripting (XSS)"},
    "xss_reflected": {"id": "CWE-79", "name": "Reflected Cross-site Scripting"},
    "xss_stored": {"id": "CWE-79", "name": "Stored Cross-site Scripting"},
    "xss_dom": {"id": "CWE-79", "name": "DOM-based Cross-site Scripting"},
    "cmd": {"id": "CWE-78", "name": "OS Command Injection"},
    "ssti": {"id": "CWE-1336", "name": "Server-Side Template Injection"},
    "ssrf": {"id": "CWE-918", "name": "Server-Side Request Forgery"},
    "lfi": {"id": "CWE-98", "name": "Improper Control of Filename for Include"},
    "rfi": {"id": "CWE-98", "name": "Improper Control of Filename for Include"},
    "xxe": {"id": "CWE-611", "name": "XML External Entity Reference"},
    "csrf": {"id": "CWE-352", "name": "Cross-Site Request Forgery"},
    "idor": {"id": "CWE-639", "name": "Authorization Bypass Through User-Controlled Key"},
    "auth_bypass": {"id": "CWE-287", "name": "Improper Authentication"},
    "jwt": {"id": "CWE-347", "name": "Improper Verification of Cryptographic Signature"},
    "session": {"id": "CWE-384", "name": "Session Fixation"},
    "cors": {"id": "CWE-942", "name": "Overly Permissive Cross-domain Whitelist"},
    "clickjack": {"id": "CWE-1021", "name": "Improper Restriction of Rendered UI Layers"},
    "open_redirect": {"id": "CWE-601", "name": "URL Redirection to Untrusted Site"},
    "nosql": {"id": "CWE-943", "name": "Improper Neutralization of Special Elements in Data Query Logic"},
    "ldap": {"id": "CWE-90", "name": "LDAP Injection"},
    "xpath": {"id": "CWE-643", "name": "Improper Neutralization of Data within XPath Expressions"},
    "rce": {"id": "CWE-94", "name": "Improper Control of Generation of Code"},
    "file_upload": {"id": "CWE-434", "name": "Unrestricted Upload of File with Dangerous Type"},
    "deserialization": {"id": "CWE-502", "name": "Deserialization of Untrusted Data"},
    "race_condition": {"id": "CWE-362", "name": "Concurrent Execution Using Shared Resource"},
    "mass_assignment": {"id": "CWE-915", "name": "Improperly Controlled Modification of Dynamically-Determined Object Attributes"},
    "rate_limit": {"id": "CWE-770", "name": "Allocation of Resources Without Limits"},
    "graphql": {"id": "CWE-200", "name": "Exposure of Sensitive Information"},
    "websocket": {"id": "CWE-1385", "name": "Missing Origin Validation in WebSockets"},
    "cache_poison": {"id": "CWE-349", "name": "Acceptance of Extraneous Untrusted Data With Trusted Data"},
    "crlf": {"id": "CWE-93", "name": "Improper Neutralization of CRLF Sequences"},
    "host_header": {"id": "CWE-644", "name": "Improper Neutralization of HTTP Headers for Scripting Syntax"},
    "subdomain_takeover": {"id": "CWE-284", "name": "Improper Access Control"},
    "http_smuggling": {"id": "CWE-444", "name": "Inconsistent Interpretation of HTTP Requests"},
    "prototype_pollution": {"id": "CWE-1321", "name": "Improperly Controlled Modification of Object Prototype Attributes"},
    "api_key_exposure": {"id": "CWE-798", "name": "Use of Hard-coded Credentials"},
    "http2_desync": {"id": "CWE-444", "name": "Inconsistent Interpretation of HTTP Requests"},
    "oauth": {"id": "CWE-346", "name": "Origin Validation Error"},
    "account_takeover": {"id": "CWE-640", "name": "Weak Password Recovery Mechanism for Forgotten Password"},
    "business_logic": {"id": "CWE-840", "name": "Business Logic Errors"},
    "parameter_tampering": {"id": "CWE-472", "name": "External Control of Assumed-Immutable Web Parameter"},
}

# VenomStrike severity → SARIF level mapping
SEVERITY_SARIF_MAP: Dict[str, str] = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
    "Info": "note",
}


class SARIFReporter:
    """Generate SARIF v2.1.0 reports from VenomStrike findings.

    Usage::

        reporter = SARIFReporter()
        sarif = reporter.generate(findings, scan_metadata={})
        reporter.write(sarif, "results.sarif")
    """

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"

    def generate(
        self,
        findings: List[Dict],
        scan_metadata: Optional[Dict] = None,
    ) -> Dict:
        """Generate a SARIF v2.1.0 document from findings.

        Args:
            findings: List of VenomStrike finding dicts.
            scan_metadata: Optional scan metadata (target_url, scan_id, etc.).

        Returns:
            SARIF document as a dict.
        """
        scan_metadata = scan_metadata or {}
        rules = self._build_rules(findings)
        results = self._build_results(findings)

        sarif = {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": TOOL_NAME,
                            "version": VERSION,
                            "fullName": f"{TOOL_NAME} v{VERSION} — {CODENAME} Edition",
                            "informationUri": "https://github.com/hamahasan441-png/VenomStrike",
                            "rules": rules,
                        },
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": scan_metadata.get(
                                "start_time",
                                datetime.now(timezone.utc).isoformat(),
                            ),
                            "endTimeUtc": scan_metadata.get(
                                "end_time",
                                datetime.now(timezone.utc).isoformat(),
                            ),
                        },
                    ],
                },
            ],
        }

        return sarif

    def _build_rules(self, findings: List[Dict]) -> List[Dict]:
        """Build SARIF rule descriptors from unique vuln types."""
        seen_types: Dict[str, Dict] = {}

        for f in findings:
            vuln_type = f.get("vuln_type", "unknown").lower()
            normalized = self._normalize_type(vuln_type)
            if normalized in seen_types:
                continue

            cwe_info = VULN_TYPE_CWE_MAP.get(normalized, {
                "id": "CWE-20", "name": "Improper Input Validation",
            })

            rule = {
                "id": f"VS-{normalized.upper().replace('_', '-')}",
                "name": cwe_info["name"],
                "shortDescription": {
                    "text": cwe_info["name"],
                },
                "fullDescription": {
                    "text": f"VenomStrike detected {cwe_info['name']} ({cwe_info['id']})",
                },
                "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_info['id'].split('-')[1]}.html",
                "properties": {
                    "tags": ["security", cwe_info["id"]],
                },
            }
            seen_types[normalized] = rule

        return list(seen_types.values())

    def _build_results(self, findings: List[Dict]) -> List[Dict]:
        """Convert VenomStrike findings to SARIF results."""
        results: List[Dict] = []

        for f in findings:
            vuln_type = f.get("vuln_type", "unknown").lower()
            normalized = self._normalize_type(vuln_type)
            severity = f.get("severity", "Medium")
            confidence = f.get("confidence", 0)
            url = f.get("url", "")
            param = f.get("param", "")
            payload = f.get("payload", "")

            cwe_info = VULN_TYPE_CWE_MAP.get(normalized, {
                "id": "CWE-20", "name": "Improper Input Validation",
            })

            # Build message
            message_parts = [
                f"{cwe_info['name']} detected",
            ]
            if param:
                message_parts.append(f"in parameter '{param}'")
            if url:
                message_parts.append(f"at {url}")
            message_parts.append(f"[Confidence: {confidence}%]")

            result = {
                "ruleId": f"VS-{normalized.upper().replace('_', '-')}",
                "level": SEVERITY_SARIF_MAP.get(severity, "warning"),
                "message": {
                    "text": " ".join(message_parts),
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": url,
                            },
                        },
                        "properties": {
                            "parameter": param,
                        },
                    },
                ],
                "properties": {
                    "venomstrike/severity": severity,
                    "venomstrike/confidence": confidence,
                    "venomstrike/vuln_type": vuln_type,
                    "venomstrike/cwe": cwe_info["id"],
                },
            }

            # Add evidence if available
            proof = f.get("proof_description", "")
            if proof:
                result["properties"]["venomstrike/proof"] = proof

            injection_url = f.get("injection_url", "")
            if injection_url:
                result["properties"]["venomstrike/injection_url"] = injection_url

            results.append(result)

        return results

    @staticmethod
    def _normalize_type(vuln_type: str) -> str:
        """Normalize vuln type for rule ID generation."""
        vt = vuln_type.lower().replace("-", "_").replace(" ", "_")
        if ":" in vt:
            vt = vt.split(":", 1)[1]
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

    def write(self, sarif_doc: Dict, filepath: str) -> str:
        """Write SARIF document to file.

        Args:
            sarif_doc: The SARIF document dict.
            filepath: Output file path (should end in .sarif or .json).

        Returns:
            The filepath written to.
        """
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(sarif_doc, f, indent=2, default=str)
        logger.info("SARIF report written to %s", filepath)
        return filepath

    def to_json(self, sarif_doc: Dict) -> str:
        """Serialize SARIF document to JSON string."""
        return json.dumps(sarif_doc, indent=2, default=str)
