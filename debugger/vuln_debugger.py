"""Vulnerability debugger — provides detailed analysis of found vulnerabilities."""
# For authorized security testing only.
from typing import Dict, List
from debugger.owasp_mapper import OWASPMapper
from debugger.attack_explainer import AttackExplainer
from debugger.code_fixer import CodeFixer
from debugger.prevention_guide import PreventionGuide


class VulnDebugger:
    def __init__(self):
        self.owasp_mapper = OWASPMapper()
        self.attack_explainer = AttackExplainer()
        self.code_fixer = CodeFixer()
        self.prevention_guide = PreventionGuide()
    
    def debug_finding(self, finding: Dict) -> Dict:
        """Create full debug report for a finding."""
        vuln_type = finding.get("vuln_type", "")
        
        debug_info = {
            "owasp_info": self.owasp_mapper.get_owasp_info(finding),
            "attack_explanation": self.attack_explainer.explain(finding),
            "fix_code": self.code_fixer.get_fix(finding),
            "prevention": self.prevention_guide.get_guide(finding),
            "references": self.owasp_mapper.get_references(vuln_type),
        }
        
        finding["debug_info"] = debug_info
        return finding
    
    def debug_all(self, findings: List[Dict]) -> List[Dict]:
        """Debug all findings."""
        return [self.debug_finding(f) for f in findings]
    
    def get_learning_path(self, vuln_type: str) -> Dict:
        """Get learning resources for a vulnerability type."""
        from debugger.learning_resources import LearningResources
        lr = LearningResources()
        return lr.get_resources(vuln_type)
    
    def generate_remediation_report(self, findings: List[Dict]) -> str:
        """Generate a text remediation report."""
        lines = ["=" * 60, "REMEDIATION REPORT", "=" * 60, ""]
        
        for i, finding in enumerate(findings, 1):
            lines.append(f"[{i}] {finding.get('vuln_type')} — {finding.get('severity')}")
            lines.append(f"    URL: {finding.get('url')}")
            lines.append(f"    Parameter: {finding.get('param')}")
            lines.append(f"    CWE: {finding.get('cwe')} | CVSS: {finding.get('cvss')}")
            
            fix = finding.get("debug_info", {}).get("fix_code", {})
            if fix:
                lines.append(f"    Fix: {fix.get('summary', 'See fix code')}")
            lines.append("")
        
        return "\n".join(lines)
