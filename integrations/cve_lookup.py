"""CVE/NVD vulnerability database lookup for VenomStrike.
For authorized security testing only.
"""
import time
from typing import Dict, List, Optional
from core.logger import log_info, log_warning, log_error


class CVELookup:
    """Query the NVD (National Vulnerability Database) for CVE details."""

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self._rate_limit_delay = 0.6 if api_key else 6.0  # NVD rate limits

    def lookup_cve(self, cve_id: str) -> Optional[Dict]:
        """Look up a specific CVE by ID."""
        import requests
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        try:
            resp = requests.get(
                self.NVD_API_BASE,
                params={"cveId": cve_id},
                headers=headers,
                timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    return self._parse_cve(vulns[0].get("cve", {}))
            elif resp.status_code == 403:
                log_warning("NVD API rate limit hit. Set NVD_API_KEY for higher limits.")
            return None
        except Exception as e:
            log_warning(f"CVE lookup error: {e}")
            return None

    def search_cves(self, keyword: str, results_per_page: int = 10) -> List[Dict]:
        """Search CVEs by keyword."""
        import requests
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        try:
            resp = requests.get(
                self.NVD_API_BASE,
                params={"keywordSearch": keyword, "resultsPerPage": results_per_page},
                headers=headers,
                timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json()
                return [
                    self._parse_cve(v.get("cve", {}))
                    for v in data.get("vulnerabilities", [])
                ]
            return []
        except Exception as e:
            log_warning(f"CVE search error: {e}")
            return []

    def search_by_cpe(self, cpe_name: str, results_per_page: int = 10) -> List[Dict]:
        """Search CVEs by CPE (Common Platform Enumeration) name."""
        import requests
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        try:
            resp = requests.get(
                self.NVD_API_BASE,
                params={"cpeName": cpe_name, "resultsPerPage": results_per_page},
                headers=headers,
                timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json()
                return [
                    self._parse_cve(v.get("cve", {}))
                    for v in data.get("vulnerabilities", [])
                ]
            return []
        except Exception as e:
            log_warning(f"CVE CPE search error: {e}")
            return []

    def enrich_finding(self, finding: Dict) -> Dict:
        """Enrich a VenomStrike finding with CVE data if applicable."""
        cwe = finding.get("cwe", "")
        if cwe and cwe.startswith("CWE-"):
            try:
                cves = self.search_cves(cwe, results_per_page=3)
                if cves:
                    finding["related_cves"] = cves[:3]
                time.sleep(self._rate_limit_delay)
            except Exception:
                pass
        return finding

    def _parse_cve(self, cve: Dict) -> Dict:
        """Parse NVD CVE entry into a simplified dict."""
        descriptions = cve.get("descriptions", [])
        desc = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        metrics = cve.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [{}])
        cvss_score = 0.0
        cvss_severity = ""
        if cvss_v31:
            cvss_data = cvss_v31[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            cvss_severity = cvss_data.get("baseSeverity", "")

        weaknesses = cve.get("weaknesses", [])
        cwe_ids = []
        for w in weaknesses:
            for d in w.get("description", []):
                if d.get("value", "").startswith("CWE-"):
                    cwe_ids.append(d["value"])

        references = [ref.get("url", "") for ref in cve.get("references", [])]

        return {
            "cve_id": cve.get("id", ""),
            "description": desc,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "cwe_ids": cwe_ids,
            "references": references[:5],
            "published": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
        }
