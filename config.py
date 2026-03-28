"""Global configuration for VenomStrike v2.0."""
import os
from dotenv import load_dotenv

load_dotenv()

VERSION = "2.0.0"
TOOL_NAME = "VenomStrike"
AUTHOR = "Security Research Tool"


def _int_env(key: str, default: int, lo: int = None, hi: int = None) -> int:
    """Read an integer from the environment with optional bounds clamping."""
    try:
        val = int(os.environ.get(key, default))
    except (ValueError, TypeError):
        val = default
    if lo is not None:
        val = max(lo, val)
    if hi is not None:
        val = min(hi, val)
    return val


def _float_env(key: str, default: float, lo: float = None, hi: float = None) -> float:
    """Read a float from the environment with optional bounds clamping."""
    try:
        val = float(os.environ.get(key, default))
    except (ValueError, TypeError):
        val = default
    if lo is not None:
        val = max(lo, val)
    if hi is not None:
        val = min(hi, val)
    return val


# HTTP Settings
DEFAULT_TIMEOUT = _int_env("VS_TIMEOUT", 10, lo=1, hi=120)
DEFAULT_THREADS = _int_env("VS_THREADS", 10, lo=1, hi=100)
MAX_THREADS = 100
DEFAULT_DELAY = _float_env("VS_DELAY", 0.5, lo=0.0, hi=60.0)
DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; VenomStrike/2.0; Security Testing)"

# Retry / resilience
RETRY_ATTEMPTS = _int_env("VS_RETRY_ATTEMPTS", 3, lo=0, hi=10)
RETRY_BACKOFF = _float_env("VS_RETRY_BACKOFF", 1.0, lo=0.1, hi=30.0)

# SSL verification (disable only for targets that require it)
VERIFY_SSL = os.environ.get("VS_VERIFY_SSL", "false").lower() == "true"

# Per-module timeout (seconds, 0 = no timeout)
MODULE_TIMEOUT = _int_env("VS_MODULE_TIMEOUT", 300, lo=0, hi=3600)

# Async scanning settings
ASYNC_ENABLED = os.environ.get("VS_ASYNC", "true").lower() == "true"
MAX_CONCURRENT_REQUESTS = _int_env("VS_MAX_CONCURRENT", 50, lo=1, hi=500)

# Confidence thresholds
MIN_CONFIDENCE = _int_env("VS_MIN_CONFIDENCE", 70, lo=0, hi=100)
VALIDATION_ATTEMPTS = _int_env("VS_VALIDATION_ATTEMPTS", 3, lo=1, hi=10)
TIMING_TOLERANCE = _float_env("VS_TIMING_TOLERANCE", 1.5, lo=0.1, hi=10.0)
CVE_ENRICH_LIMIT = _int_env("VS_CVE_ENRICH_LIMIT", 20, lo=1, hi=200)

# Injection engine — advanced settings
WAF_EVASION_ENABLED = os.environ.get("VS_WAF_EVASION", "true").lower() == "true"
EARLY_TERMINATION = os.environ.get("VS_EARLY_TERMINATION", "true").lower() == "true"
CONFIRMATION_ENABLED = os.environ.get("VS_CONFIRMATION", "true").lower() == "true"

# Database
DB_PATH = os.environ.get("VS_DB_PATH", os.path.join(os.path.dirname(__file__), "venomstrike.db"))

# Reports
REPORTS_DIR = os.environ.get("VS_REPORTS_DIR", os.path.join(os.path.dirname(__file__), "reports"))

# Severity levels
SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"
SEVERITY_INFO = "Info"

SEVERITY_COLORS = {
    "Critical": "#ff0040",
    "High": "#ff6600",
    "Medium": "#ffcc00",
    "Low": "#0099ff",
    "Info": "#888888",
}

# Flask
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", os.urandom(32).hex())
FLASK_DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
FLASK_HOST = os.environ.get("FLASK_HOST", "127.0.0.1")
FLASK_PORT = _int_env("FLASK_PORT", 5000, lo=1, hi=65535)

# Tool Integrations
NMAP_ENABLED = os.environ.get("VS_NMAP_ENABLED", "false").lower() == "true"
NMAP_PATH = os.environ.get("VS_NMAP_PATH", "nmap")

SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")

ZAP_ENABLED = os.environ.get("VS_ZAP_ENABLED", "false").lower() == "true"
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")
ZAP_PROXY = os.environ.get("ZAP_PROXY", "http://127.0.0.1:8080")

NUCLEI_ENABLED = os.environ.get("VS_NUCLEI_ENABLED", "false").lower() == "true"
NUCLEI_PATH = os.environ.get("VS_NUCLEI_PATH", "nuclei")
NUCLEI_TEMPLATES_DIR = os.environ.get("VS_NUCLEI_TEMPLATES", "")

# CVE / NVD lookup
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

# Legal
LEGAL_DISCLAIMER = """
⚠️  LEGAL DISCLAIMER ⚠️
VenomStrike is for authorized security testing ONLY.
You must have explicit written permission to test any system.
Unauthorized testing is illegal and unethical.
The authors are not responsible for misuse.
"""
