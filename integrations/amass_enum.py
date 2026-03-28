"""Amass subdomain enumeration integration.
For authorized security testing only.
"""
import json
import logging
import shutil
import subprocess
from typing import Dict, List, Optional

from config import AMASS_ENABLED, AMASS_PATH

logger = logging.getLogger("venomstrike.integrations.amass")


class AmassEnum:
    """Enumerate subdomains using the Amass OWASP tool.

    Amass performs DNS enumeration, scraping, and brute-force to discover
    subdomains of a target domain.  It must be installed separately.

    For authorised security testing only.
    """

    def __init__(self, binary_path: str = None):
        self.binary = binary_path or AMASS_PATH

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return *True* if Amass is installed and enabled in config."""
        if not AMASS_ENABLED:
            return False
        return shutil.which(self.binary) is not None

    # ------------------------------------------------------------------
    # Passive enumeration (no direct target interaction)
    # ------------------------------------------------------------------

    def passive_enum(self, domain: str, timeout: int = 300) -> List[str]:
        """Run a passive subdomain enumeration.

        Args:
            domain: Target domain (e.g. ``example.com``).
            timeout: Maximum seconds to wait for Amass.

        Returns:
            A sorted list of discovered subdomains.
        """
        if not self.is_available():
            logger.warning("Amass is not available or not enabled")
            return []

        cmd = [self.binary, "enum", "-passive", "-d", domain, "-json", "-"]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            return self._parse_json_lines(result.stdout)
        except subprocess.TimeoutExpired:
            logger.warning("Amass passive enum timed out after %ds", timeout)
            return []
        except FileNotFoundError:
            logger.error("Amass binary not found at %s", self.binary)
            return []
        except Exception as exc:
            logger.error("Amass error: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Active enumeration (sends DNS queries to target infrastructure)
    # ------------------------------------------------------------------

    def active_enum(
        self, domain: str, *, brute: bool = False, timeout: int = 600,
    ) -> List[str]:
        """Run an active subdomain enumeration.

        Args:
            domain: Target domain.
            brute: If *True*, include brute-force subdomain guessing.
            timeout: Maximum seconds to wait.

        Returns:
            A sorted list of discovered subdomains.
        """
        if not self.is_available():
            logger.warning("Amass is not available or not enabled")
            return []

        cmd = [self.binary, "enum", "-active", "-d", domain, "-json", "-"]
        if brute:
            cmd.append("-brute")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            return self._parse_json_lines(result.stdout)
        except subprocess.TimeoutExpired:
            logger.warning("Amass active enum timed out after %ds", timeout)
            return []
        except FileNotFoundError:
            logger.error("Amass binary not found at %s", self.binary)
            return []
        except Exception as exc:
            logger.error("Amass error: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Result structure
    # ------------------------------------------------------------------

    def enum_with_details(self, domain: str, timeout: int = 600) -> List[Dict]:
        """Run enumeration and return structured results.

        Each result dict has keys: ``name``, ``domain``, ``addresses``,
        ``sources``.
        """
        if not self.is_available():
            return []

        cmd = [self.binary, "enum", "-active", "-d", domain, "-json", "-"]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            return self._parse_json_details(result.stdout)
        except Exception as exc:
            logger.error("Amass detailed enum error: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_json_lines(output: str) -> List[str]:
        """Parse Amass JSON-lines output and extract unique hostnames."""
        subdomains = set()
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                name = data.get("name", "")
                if name:
                    subdomains.add(name.lower())
            except json.JSONDecodeError:
                # Amass sometimes outputs plain text lines
                if "." in line and " " not in line:
                    subdomains.add(line.lower())
        return sorted(subdomains)

    @staticmethod
    def _parse_json_details(output: str) -> List[Dict]:
        """Parse Amass JSON-lines output into structured dicts."""
        results = []
        seen = set()
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                name = data.get("name", "").lower()
                if name and name not in seen:
                    seen.add(name)
                    results.append({
                        "name": name,
                        "domain": data.get("domain", ""),
                        "addresses": [
                            a.get("ip", "") for a in data.get("addresses", [])
                        ],
                        "sources": data.get("sources", []),
                    })
            except json.JSONDecodeError:
                continue
        return results
