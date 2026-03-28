"""Nmap network scanner integration for VenomStrike.
For authorized security testing only.
"""
import shutil
from typing import Dict, List, Optional
from core.logger import log_info, log_warning, log_error


class NmapScanner:
    """Wrapper around python-nmap for port scanning and service detection."""

    def __init__(self, nmap_path: str = "nmap"):
        self.nmap_path = nmap_path
        self._scanner = None

    def is_available(self) -> bool:
        """Check if nmap is installed and accessible."""
        if shutil.which(self.nmap_path) is None:
            log_warning("Nmap not found. Install nmap for network scanning.")
            return False
        try:
            import nmap
            self._scanner = nmap.PortScanner(nmap_search_path=(self.nmap_path,))
            return True
        except ImportError:
            log_warning("python-nmap not installed. Run: pip install python-nmap")
            return False
        except Exception as e:
            log_error(f"Nmap init error: {e}")
            return False

    def quick_scan(self, target: str) -> Dict:
        """Run a quick TCP SYN scan on common ports."""
        if not self._scanner and not self.is_available():
            return {"error": "Nmap not available"}
        try:
            log_info(f"Nmap quick scan: {target}")
            self._scanner.scan(target, arguments="-sV -T4 --top-ports 100 --open")
            return self._parse_results(target)
        except Exception as e:
            log_error(f"Nmap scan error: {e}")
            return {"error": str(e)}

    def service_scan(self, target: str, ports: str = "1-1000") -> Dict:
        """Run service version detection scan."""
        if not self._scanner and not self.is_available():
            return {"error": "Nmap not available"}
        try:
            log_info(f"Nmap service scan: {target} ports={ports}")
            self._scanner.scan(target, ports, arguments="-sV -sC")
            return self._parse_results(target)
        except Exception as e:
            log_error(f"Nmap scan error: {e}")
            return {"error": str(e)}

    def vuln_scan(self, target: str) -> Dict:
        """Run Nmap vulnerability detection scripts."""
        if not self._scanner and not self.is_available():
            return {"error": "Nmap not available"}
        try:
            log_info(f"Nmap vuln scan: {target}")
            self._scanner.scan(target, arguments="-sV --script=vuln --top-ports 50")
            return self._parse_results(target)
        except Exception as e:
            log_error(f"Nmap scan error: {e}")
            return {"error": str(e)}

    def _parse_results(self, target: str) -> Dict:
        """Parse nmap scan results into structured data."""
        results = {"target": target, "hosts": [], "open_ports": [], "services": []}
        try:
            for host in self._scanner.all_hosts():
                host_info = {
                    "ip": host,
                    "state": self._scanner[host].state(),
                    "hostnames": [h["name"] for h in self._scanner[host].hostnames() if h["name"]],
                    "ports": [],
                }
                for proto in self._scanner[host].all_protocols():
                    ports = self._scanner[host][proto].keys()
                    for port in sorted(ports):
                        port_info = self._scanner[host][proto][port]
                        entry = {
                            "port": port,
                            "protocol": proto,
                            "state": port_info.get("state", ""),
                            "service": port_info.get("name", ""),
                            "version": port_info.get("version", ""),
                            "product": port_info.get("product", ""),
                            "extra": port_info.get("extrainfo", ""),
                        }
                        host_info["ports"].append(entry)
                        if entry["state"] == "open":
                            results["open_ports"].append(port)
                            results["services"].append(
                                f"{port}/{proto} {entry['service']} {entry['version']}".strip()
                            )
                results["hosts"].append(host_info)
        except Exception as e:
            log_warning(f"Nmap parse warning: {e}")
        return results
