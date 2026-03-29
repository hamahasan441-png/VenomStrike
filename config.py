"""Global configuration for VenomStrike v10.0 — Phoenix Edition."""
import os
from dotenv import load_dotenv

load_dotenv()

VERSION = "10.0.0"
CODENAME = "Phoenix"
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
DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; VenomStrike/10.0-Phoenix; Security Testing)"

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

# ── Scan depth ──────────────────────────────────────────────────
# Controls how thorough each scan phase is. Allowed values:
#   quick    — fast surface-level scan (less payloads, shallow crawl)
#   standard — balanced depth (default, same behaviour as v2)
#   deep     — more payloads, deeper crawl, higher validation
#   full     — maximum depth: all payloads, deepest crawl, max validation
#   quantum  — v4.0 ultra-deep: triple-marker confirmation, cross-correlation,
#              entropy analysis, statistical confidence — maximum accuracy
#   titan    — v7.0 ultimate: all quantum features + OOB verification,
#              payload mutation, robust timing, WAF fingerprinting
#   hydra    — v8.0 supreme: all titan features + smart payload selection,
#              attack chain correlation, Bayesian confidence scoring,
#              response intelligence, adaptive multi-stage exploitation
#   chimera  — v9.0 apex: all hydra features + adaptive rate limiting,
#              cross-module vulnerability correlation, dynamic scan
#              optimization, SARIF CI/CD output, parameter tampering
#   phoenix  — v10.0 ultimate: all chimera features + smart parameter
#              deduplication, context-aware validation, intelligent payload
#              minimization, vulnerability impact analysis, adaptive scan profiling
_VALID_DEPTHS = ("quick", "standard", "deep", "full", "quantum", "titan", "hydra", "chimera", "phoenix")
SCAN_DEPTH = os.environ.get("VS_SCAN_DEPTH", "standard").lower()
if SCAN_DEPTH not in _VALID_DEPTHS:
    SCAN_DEPTH = "standard"

# Depth presets — tunable knobs derived from depth level
DEPTH_PRESETS = {
    "quick": {
        "crawl_depth": 1,
        "max_crawl_pages": 20,
        "dir_brute_limit": 50,
        "api_brute_limit": 25,
        "payload_limit": 5,
        "validation_attempts": 1,
        "min_confidence": 80,
    },
    "standard": {
        "crawl_depth": 2,
        "max_crawl_pages": 50,
        "dir_brute_limit": 100,
        "api_brute_limit": 50,
        "payload_limit": 15,
        "validation_attempts": 3,
        "min_confidence": 70,
    },
    "deep": {
        "crawl_depth": 3,
        "max_crawl_pages": 150,
        "dir_brute_limit": 250,
        "api_brute_limit": 120,
        "payload_limit": 30,
        "validation_attempts": 5,
        "min_confidence": 60,
    },
    "full": {
        "crawl_depth": 5,
        "max_crawl_pages": 500,
        "dir_brute_limit": 0,  # 0 = unlimited (use full wordlist)
        "api_brute_limit": 0,
        "payload_limit": 0,
        "validation_attempts": 7,
        "min_confidence": 50,
    },
    "quantum": {
        "crawl_depth": 7,
        "max_crawl_pages": 1000,
        "dir_brute_limit": 0,
        "api_brute_limit": 0,
        "payload_limit": 0,
        "validation_attempts": 10,
        "min_confidence": 40,
        "cross_correlation": True,
        "entropy_analysis": True,
        "triple_confirm": True,
        "statistical_confidence": True,
    },
    "titan": {
        "crawl_depth": 10,
        "max_crawl_pages": 2000,
        "dir_brute_limit": 0,
        "api_brute_limit": 0,
        "payload_limit": 0,
        "validation_attempts": 15,
        "min_confidence": 30,
        "cross_correlation": True,
        "entropy_analysis": True,
        "triple_confirm": True,
        "statistical_confidence": True,
        "oob_verification": True,
        "payload_mutation": True,
        "robust_timing": True,
        "waf_fingerprinting": True,
    },
    "hydra": {
        "crawl_depth": 15,
        "max_crawl_pages": 5000,
        "dir_brute_limit": 0,
        "api_brute_limit": 0,
        "payload_limit": 0,
        "validation_attempts": 20,
        "min_confidence": 20,
        # Quantum features
        "cross_correlation": True,
        "entropy_analysis": True,
        "triple_confirm": True,
        "statistical_confidence": True,
        # Titan features
        "oob_verification": True,
        "payload_mutation": True,
        "robust_timing": True,
        "waf_fingerprinting": True,
        # Hydra v8.0 features
        "smart_payload_selection": True,
        "attack_chain_correlation": True,
        "bayesian_scoring": True,
        "response_intelligence": True,
        "adaptive_exploitation": True,
    },
    "chimera": {
        "crawl_depth": 20,
        "max_crawl_pages": 10000,
        "dir_brute_limit": 0,
        "api_brute_limit": 0,
        "payload_limit": 0,
        "validation_attempts": 25,
        "min_confidence": 15,
        # Quantum features
        "cross_correlation": True,
        "entropy_analysis": True,
        "triple_confirm": True,
        "statistical_confidence": True,
        # Titan features
        "oob_verification": True,
        "payload_mutation": True,
        "robust_timing": True,
        "waf_fingerprinting": True,
        # Hydra v8.0 features
        "smart_payload_selection": True,
        "attack_chain_correlation": True,
        "bayesian_scoring": True,
        "response_intelligence": True,
        "adaptive_exploitation": True,
        # Chimera v9.0 features
        "adaptive_rate_limiting": True,
        "vulnerability_correlation": True,
        "scan_optimization": True,
        "sarif_output": True,
        "parameter_tampering": True,
    },
    "phoenix": {
        "crawl_depth": 25,
        "max_crawl_pages": 15000,
        "dir_brute_limit": 0,
        "api_brute_limit": 0,
        "payload_limit": 0,
        "validation_attempts": 30,
        "min_confidence": 10,
        # Quantum features
        "cross_correlation": True,
        "entropy_analysis": True,
        "triple_confirm": True,
        "statistical_confidence": True,
        # Titan features
        "oob_verification": True,
        "payload_mutation": True,
        "robust_timing": True,
        "waf_fingerprinting": True,
        # Hydra v8.0 features
        "smart_payload_selection": True,
        "attack_chain_correlation": True,
        "bayesian_scoring": True,
        "response_intelligence": True,
        "adaptive_exploitation": True,
        # Chimera v9.0 features
        "adaptive_rate_limiting": True,
        "vulnerability_correlation": True,
        "scan_optimization": True,
        "sarif_output": True,
        "parameter_tampering": True,
        # Phoenix v10.0 features
        "param_deduplication": True,
        "context_validation": True,
        "payload_minimization": True,
        "impact_analysis": True,
        "scan_profiling": True,
    },
}

# Confidence thresholds
MIN_CONFIDENCE = _int_env("VS_MIN_CONFIDENCE", 70, lo=0, hi=100)
VALIDATION_ATTEMPTS = _int_env("VS_VALIDATION_ATTEMPTS", 3, lo=1, hi=10)
TIMING_TOLERANCE = _float_env("VS_TIMING_TOLERANCE", 1.5, lo=0.1, hi=10.0)
CVE_ENRICH_LIMIT = _int_env("VS_CVE_ENRICH_LIMIT", 20, lo=1, hi=200)

# Quantum verification settings (v4.0)
QUANTUM_CROSS_CORRELATION = os.environ.get("VS_CROSS_CORRELATION", "true").lower() == "true"
QUANTUM_ENTROPY_THRESHOLD = _float_env("VS_ENTROPY_THRESHOLD", 0.3, lo=0.0, hi=1.0)
QUANTUM_TRIPLE_CONFIRM = os.environ.get("VS_TRIPLE_CONFIRM", "true").lower() == "true"
QUANTUM_STATISTICAL_MIN_SAMPLES = _int_env("VS_STAT_MIN_SAMPLES", 5, lo=3, hi=20)

# Injection engine — advanced settings
WAF_EVASION_ENABLED = os.environ.get("VS_WAF_EVASION", "true").lower() == "true"
EARLY_TERMINATION = os.environ.get("VS_EARLY_TERMINATION", "true").lower() == "true"
CONFIRMATION_ENABLED = os.environ.get("VS_CONFIRMATION", "true").lower() == "true"

# Titan verification settings (v7.0)
OOB_VERIFICATION_ENABLED = os.environ.get("VS_OOB_VERIFICATION", "true").lower() == "true"
OOB_CALLBACK_DOMAIN = os.environ.get("VS_OOB_CALLBACK_DOMAIN", "")
OOB_CALLBACK_TIMEOUT = _int_env("VS_OOB_CALLBACK_TIMEOUT", 10, lo=1, hi=60)
PAYLOAD_MUTATION_ENABLED = os.environ.get("VS_PAYLOAD_MUTATION", "true").lower() == "true"
ROBUST_TIMING_ENABLED = os.environ.get("VS_ROBUST_TIMING", "true").lower() == "true"
ROBUST_TIMING_PERCENTILE = _float_env("VS_ROBUST_TIMING_PERCENTILE", 95.0, lo=50.0, hi=99.9)
WAF_FINGERPRINT_ENABLED = os.environ.get("VS_WAF_FINGERPRINT", "true").lower() == "true"

# Hydra intelligence settings (v8.0)
SMART_PAYLOAD_SELECTION = os.environ.get("VS_SMART_PAYLOAD", "true").lower() == "true"
ATTACK_CHAIN_CORRELATION = os.environ.get("VS_ATTACK_CHAIN", "true").lower() == "true"
BAYESIAN_SCORING_ENABLED = os.environ.get("VS_BAYESIAN_SCORING", "true").lower() == "true"
RESPONSE_INTELLIGENCE_ENABLED = os.environ.get("VS_RESPONSE_INTELLIGENCE", "true").lower() == "true"
ADAPTIVE_EXPLOITATION = os.environ.get("VS_ADAPTIVE_EXPLOITATION", "true").lower() == "true"
BAYESIAN_PRIOR_CONFIDENCE = _float_env("VS_BAYESIAN_PRIOR", 0.3, lo=0.01, hi=0.99)
ATTACK_CHAIN_MAX_DEPTH = _int_env("VS_CHAIN_MAX_DEPTH", 5, lo=1, hi=20)
SMART_PAYLOAD_TOP_N = _int_env("VS_SMART_TOP_N", 25, lo=5, hi=200)

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

# Amass subdomain enumeration
AMASS_ENABLED = os.environ.get("VS_AMASS_ENABLED", "false").lower() == "true"
AMASS_PATH = os.environ.get("VS_AMASS_PATH", "amass")

# Wappalyzer technology fingerprinting
WAPPALYZER_ENABLED = os.environ.get("VS_WAPPALYZER_ENABLED", "false").lower() == "true"

# Chimera intelligence settings (v9.0)
ADAPTIVE_RATE_LIMITING = os.environ.get("VS_ADAPTIVE_RATE_LIMIT", "true").lower() == "true"
RATE_LIMIT_MIN_DELAY = _float_env("VS_RATE_LIMIT_MIN_DELAY", 0.1, lo=0.0, hi=10.0)
RATE_LIMIT_MAX_DELAY = _float_env("VS_RATE_LIMIT_MAX_DELAY", 5.0, lo=0.1, hi=60.0)
RATE_LIMIT_ERROR_THRESHOLD = _int_env("VS_RATE_LIMIT_ERROR_THRESHOLD", 3, lo=1, hi=20)
VULNERABILITY_CORRELATION_ENABLED = os.environ.get("VS_VULN_CORRELATION", "true").lower() == "true"
SCAN_OPTIMIZATION_ENABLED = os.environ.get("VS_SCAN_OPTIMIZATION", "true").lower() == "true"
SARIF_OUTPUT_ENABLED = os.environ.get("VS_SARIF_OUTPUT", "false").lower() == "true"
PARAMETER_TAMPERING_ENABLED = os.environ.get("VS_PARAM_TAMPERING", "true").lower() == "true"
SCAN_OPTIMIZER_MIN_ENDPOINTS = _int_env("VS_OPTIMIZER_MIN_ENDPOINTS", 10, lo=1, hi=100)
CORRELATION_MIN_FINDINGS = _int_env("VS_CORRELATION_MIN_FINDINGS", 2, lo=1, hi=50)

# Phoenix intelligence settings (v10.0)
PARAM_DEDUP_ENABLED = os.environ.get("VS_PARAM_DEDUP", "true").lower() == "true"
PARAM_DEDUP_SIMILARITY_THRESHOLD = _float_env("VS_PARAM_DEDUP_THRESHOLD", 0.8, lo=0.1, hi=1.0)
PARAM_DEDUP_MAX_PER_TYPE = _int_env("VS_PARAM_DEDUP_MAX", 5, lo=1, hi=50)
CONTEXT_VALIDATION_ENABLED = os.environ.get("VS_CONTEXT_VALIDATION", "true").lower() == "true"
CONTEXT_VALIDATION_BOOST = _int_env("VS_CONTEXT_BOOST", 10, lo=0, hi=30)
CONTEXT_VALIDATION_PENALTY = _int_env("VS_CONTEXT_PENALTY", 25, lo=0, hi=50)
PAYLOAD_MINIMIZER_ENABLED = os.environ.get("VS_PAYLOAD_MINIMIZER", "true").lower() == "true"
PAYLOAD_MINIMIZER_MAX_RATIO = _float_env("VS_PAYLOAD_MAX_RATIO", 0.5, lo=0.1, hi=1.0)
PAYLOAD_MINIMIZER_MIN_PAYLOADS = _int_env("VS_PAYLOAD_MIN_COUNT", 5, lo=1, hi=100)
IMPACT_ANALYSIS_ENABLED = os.environ.get("VS_IMPACT_ANALYSIS", "true").lower() == "true"
SCAN_PROFILER_ENABLED = os.environ.get("VS_SCAN_PROFILER", "true").lower() == "true"
SCAN_PROFILER_WINDOW_SIZE = _int_env("VS_PROFILER_WINDOW", 100, lo=10, hi=1000)
SCAN_PROFILER_ERROR_THRESHOLD = _float_env("VS_PROFILER_ERROR_THRESHOLD", 0.3, lo=0.05, hi=0.9)
SCAN_PROFILER_LATENCY_MULTIPLIER = _float_env("VS_PROFILER_LATENCY_MULT", 3.0, lo=1.5, hi=10.0)

# Legal
LEGAL_DISCLAIMER = """
⚠️  LEGAL DISCLAIMER ⚠️
VenomStrike is for authorized security testing ONLY.
You must have explicit written permission to test any system.
Unauthorized testing is illegal and unethical.
The authors are not responsible for misuse.
"""
