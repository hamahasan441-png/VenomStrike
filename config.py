"""Global configuration for VenomStrike."""
import os

VERSION = "1.0.0"
TOOL_NAME = "VenomStrike"
AUTHOR = "Security Research Tool"

# HTTP Settings
DEFAULT_TIMEOUT = 10
DEFAULT_THREADS = 10
MAX_THREADS = 100
DEFAULT_DELAY = 0.5
DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; VenomStrike/1.0; Security Testing)"

# Confidence thresholds
MIN_CONFIDENCE = 70  # Only report findings >= 70%
VALIDATION_ATTEMPTS = 3

# Database
DB_PATH = os.path.join(os.path.dirname(__file__), "venomstrike.db")

# Reports
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")

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
FLASK_DEBUG = False
FLASK_HOST = "127.0.0.1"
FLASK_PORT = 5000

# Legal
LEGAL_DISCLAIMER = """
⚠️  LEGAL DISCLAIMER ⚠️
VenomStrike is for authorized security testing ONLY.
You must have explicit written permission to test any system.
Unauthorized testing is illegal and unethical.
The authors are not responsible for misuse.
"""
