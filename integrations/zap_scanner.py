"""OWASP ZAP API integration for VenomStrike.
For authorized security testing only.
"""
import time
from typing import Dict, List, Optional
from core.logger import log_info, log_warning, log_error


class ZAPScanner:
    """Wrapper around OWASP ZAP REST API for automated scanning."""

    def __init__(self, api_key: str = "", proxy: str = "http://127.0.0.1:8080"):
        self.api_key = api_key
        self.proxy = proxy
        self.base_url = f"{proxy}"

    def is_available(self) -> bool:
        """Check if ZAP is running and accessible."""
        import requests
        try:
            resp = requests.get(
                f"{self.base_url}/JSON/core/view/version/",
                params={"apikey": self.api_key},
                timeout=5,
            )
            if resp.status_code == 200:
                log_info(f"ZAP connected: v{resp.json().get('version', 'unknown')}")
                return True
            return False
        except Exception:
            log_warning("OWASP ZAP not running. Start ZAP with API enabled.")
            return False

    def spider(self, target: str, max_depth: int = 5) -> Dict:
        """Run ZAP spider on target."""
        import requests
        try:
            log_info(f"ZAP spider: {target}")
            resp = requests.get(
                f"{self.base_url}/JSON/spider/action/scan/",
                params={"apikey": self.api_key, "url": target, "maxChildren": max_depth},
                timeout=10,
            )
            scan_id = resp.json().get("scan", "0")

            # Wait for spider to complete
            while True:
                status_resp = requests.get(
                    f"{self.base_url}/JSON/spider/view/status/",
                    params={"apikey": self.api_key, "scanId": scan_id},
                    timeout=10,
                )
                progress = int(status_resp.json().get("status", "0"))
                if progress >= 100:
                    break
                time.sleep(2)

            results_resp = requests.get(
                f"{self.base_url}/JSON/spider/view/results/",
                params={"apikey": self.api_key, "scanId": scan_id},
                timeout=10,
            )
            urls = results_resp.json().get("results", [])
            return {"scan_id": scan_id, "urls_found": len(urls), "urls": urls[:100]}
        except Exception as e:
            log_error(f"ZAP spider error: {e}")
            return {"error": str(e)}

    def active_scan(self, target: str) -> Dict:
        """Run ZAP active scan on target."""
        import requests
        try:
            log_info(f"ZAP active scan: {target}")
            resp = requests.get(
                f"{self.base_url}/JSON/ascan/action/scan/",
                params={"apikey": self.api_key, "url": target},
                timeout=10,
            )
            scan_id = resp.json().get("scan", "0")

            while True:
                status_resp = requests.get(
                    f"{self.base_url}/JSON/ascan/view/status/",
                    params={"apikey": self.api_key, "scanId": scan_id},
                    timeout=10,
                )
                progress = int(status_resp.json().get("status", "0"))
                if progress >= 100:
                    break
                time.sleep(5)

            return self.get_alerts(target)
        except Exception as e:
            log_error(f"ZAP active scan error: {e}")
            return {"error": str(e)}

    def get_alerts(self, target: str = "") -> Dict:
        """Get all ZAP alerts for a target."""
        import requests
        try:
            params = {"apikey": self.api_key, "start": 0, "count": 100}
            if target:
                params["baseurl"] = target
            resp = requests.get(
                f"{self.base_url}/JSON/alert/view/alerts/",
                params=params,
                timeout=10,
            )
            raw_alerts = resp.json().get("alerts", [])
            alerts = [
                {
                    "alert": a.get("alert", ""),
                    "risk": a.get("risk", ""),
                    "confidence": a.get("confidence", ""),
                    "url": a.get("url", ""),
                    "param": a.get("param", ""),
                    "description": a.get("description", "")[:300],
                    "solution": a.get("solution", "")[:300],
                    "reference": a.get("reference", ""),
                    "cweid": a.get("cweid", ""),
                    "wascid": a.get("wascid", ""),
                }
                for a in raw_alerts
            ]
            return {"alerts": alerts, "total": len(alerts)}
        except Exception as e:
            log_error(f"ZAP alerts error: {e}")
            return {"error": str(e)}

    def get_summary(self, target: str) -> Dict:
        """Get alert summary counts by risk level."""
        alerts_data = self.get_alerts(target)
        if "error" in alerts_data:
            return alerts_data
        alerts = alerts_data.get("alerts", [])
        summary = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for a in alerts:
            risk = a.get("risk", "Informational")
            summary[risk] = summary.get(risk, 0) + 1
        return {"summary": summary, "total": len(alerts)}
