"""Global configuration for VenomStrike v2.0."""
import os
from dotenv import load_dotenv

load_dotenv()

VERSION = "2.0.0"
TOOL_NAME = "VenomStrike"
AUTHOR = "Security Research Tool"

# HTTP Settings
DEFAULT_TIMEOUT = int(os.environ.get("VS_TIMEOUT", 10))
DEFAULT_THREADS = int(os.environ.get("VS_THREADS", 10))
MAX_THREADS = 100
DEFAULT_DELAY = float(os.environ.get("VS_DELAY", 0.5))
DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; VenomStrike/2.0; Security Testing)"

# Async scanning settings
ASYNC_ENABLED = os.environ.get("VS_ASYNC", "true").lower() == "true"
MAX_CONCURRENT_REQUESTS = int(os.environ.get("VS_MAX_CONCURRENT", 50))

# Confidence thresholds
MIN_CONFIDENCE = int(os.environ.get("VS_MIN_CONFIDENCE", 70))
VALIDATION_ATTEMPTS = 3
CVE_ENRICH_LIMIT = int(os.environ.get("VS_CVE_ENRICH_LIMIT", 20))

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
FLASK_PORT = int(os.environ.get("FLASK_PORT", 5000))

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
