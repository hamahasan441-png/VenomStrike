"""Nuclei vulnerability scanner integration for VenomStrike.
For authorized security testing only.
"""
import json
import shutil
import subprocess
from typing import Dict, List, Optional
from core.logger import log_info, log_warning, log_error


class NucleiRunner:
    """Wrapper around Project Discovery's Nuclei scanner."""

    def __init__(self, nuclei_path: str = "nuclei", templates_dir: str = ""):
        self.nuclei_path = nuclei_path
        self.templates_dir = templates_dir

    def is_available(self) -> bool:
        """Check if nuclei is installed."""
        if shutil.which(self.nuclei_path) is None:
            log_warning("Nuclei not found. Install from: https://github.com/projectdiscovery/nuclei")
            return False
        return True

    def scan(self, target: str, severity: str = "", tags: str = "",
             templates: str = "", rate_limit: int = 50) -> List[Dict]:
        """Run nuclei scan against target."""
        if not self.is_available():
            return []

        cmd = [self.nuclei_path, "-u", target, "-jsonl", "-silent", "-rate-limit", str(rate_limit)]

        if severity:
            cmd.extend(["-severity", severity])
        if tags:
            cmd.extend(["-tags", tags])
        if templates:
            cmd.extend(["-t", templates])
        elif self.templates_dir:
            cmd.extend(["-t", self.templates_dir])

        try:
            log_info(f"Nuclei scan: {target}")
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600
            )
            return self._parse_results(result.stdout)
        except subprocess.TimeoutExpired:
            log_warning("Nuclei scan timed out after 10 minutes")
            return []
        except Exception as e:
            log_error(f"Nuclei error: {e}")
            return []

    def scan_with_templates(self, target: str, template_ids: List[str]) -> List[Dict]:
        """Run nuclei with specific template IDs."""
        if not self.is_available():
            return []
        cmd = [self.nuclei_path, "-u", target, "-jsonl", "-silent"]
        for tid in template_ids:
            cmd.extend(["-id", tid])
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return self._parse_results(result.stdout)
        except Exception as e:
            log_error(f"Nuclei error: {e}")
            return []

    def _parse_results(self, output: str) -> List[Dict]:
        """Parse nuclei JSON line output."""
        findings = []
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                findings.append({
                    "template_id": data.get("template-id", ""),
                    "name": data.get("info", {}).get("name", ""),
                    "severity": data.get("info", {}).get("severity", "info").capitalize(),
                    "description": data.get("info", {}).get("description", ""),
                    "matched_at": data.get("matched-at", ""),
                    "matcher_name": data.get("matcher-name", ""),
                    "type": data.get("type", ""),
                    "host": data.get("host", ""),
                    "tags": data.get("info", {}).get("tags", []),
                    "reference": data.get("info", {}).get("reference", []),
                    "curl_command": data.get("curl-command", ""),
                })
            except json.JSONDecodeError:
                continue
        return findings
