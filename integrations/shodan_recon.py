"""Shodan intelligence integration for VenomStrike.
For authorized security testing only.
"""
from typing import Dict, List, Optional
from core.logger import log_info, log_warning, log_error


class ShodanRecon:
    """Query Shodan for host intelligence and passive reconnaissance."""

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self._api = None

    def is_available(self) -> bool:
        """Check if Shodan API is configured."""
        if not self.api_key:
            log_warning("Shodan API key not set. Set SHODAN_API_KEY env variable.")
            return False
        try:
            import shodan
            self._api = shodan.Shodan(self.api_key)
            return True
        except ImportError:
            log_warning("shodan not installed. Run: pip install shodan")
            return False

    def host_lookup(self, ip: str) -> Optional[Dict]:
        """Look up a host on Shodan by IP address."""
        if not self._api and not self.is_available():
            return None
        try:
            log_info(f"Shodan host lookup: {ip}")
            host = self._api.host(ip)
            return {
                "ip": host.get("ip_str", ip),
                "os": host.get("os"),
                "organization": host.get("org", ""),
                "isp": host.get("isp", ""),
                "asn": host.get("asn", ""),
                "hostnames": host.get("hostnames", []),
                "domains": host.get("domains", []),
                "ports": host.get("ports", []),
                "vulns": host.get("vulns", []),
                "country": host.get("country_name", ""),
                "city": host.get("city", ""),
                "last_update": host.get("last_update", ""),
                "services": [
                    {
                        "port": s.get("port"),
                        "transport": s.get("transport", "tcp"),
                        "product": s.get("product", ""),
                        "version": s.get("version", ""),
                        "banner": s.get("data", "")[:200],
                    }
                    for s in host.get("data", [])
                ],
            }
        except Exception as e:
            log_warning(f"Shodan lookup error: {e}")
            return None

    def search(self, query: str, max_results: int = 10) -> List[Dict]:
        """Search Shodan with a query string."""
        if not self._api and not self.is_available():
            return []
        try:
            log_info(f"Shodan search: {query}")
            results = self._api.search(query, limit=max_results)
            return [
                {
                    "ip": r.get("ip_str", ""),
                    "port": r.get("port"),
                    "org": r.get("org", ""),
                    "product": r.get("product", ""),
                    "version": r.get("version", ""),
                    "hostnames": r.get("hostnames", []),
                    "banner": r.get("data", "")[:200],
                }
                for r in results.get("matches", [])
            ]
        except Exception as e:
            log_warning(f"Shodan search error: {e}")
            return []

    def dns_resolve(self, hostnames: List[str]) -> Dict:
        """Resolve hostnames using Shodan DNS."""
        if not self._api and not self.is_available():
            return {}
        try:
            return self._api.dns.domain_info(hostnames[0]) if hostnames else {}
        except Exception as e:
            log_warning(f"Shodan DNS error: {e}")
            return {}
