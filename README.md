# 🗡️ VenomStrike v9.0 — Chimera Edition

> **Advanced Security Testing & Vulnerability Debugging Framework — Chimera Edition — Educational Tool**

⚠️ **LEGAL DISCLAIMER**: VenomStrike is for **authorized security testing ONLY**. You must have explicit written permission to test any system. Unauthorized testing is illegal and unethical.

---

## Features

### Core Scanning Engine
- **35+ vulnerability modules** across 6 categories: Injection, Client-Side, Server-Side, Auth, Logic, Advanced
- **Multi-threaded scanning** with configurable concurrency
- **Automatic reconnaissance**: endpoint discovery, tech fingerprinting, attack surface mapping
- **False positive filtering** with multi-stage validation and confidence scoring
- **Learning mode**: fix code, explanations, and OWASP mapping for every finding

### Chimera Intelligence Engine (v9.0)

VenomStrike v9.0 "Chimera" is the apex edition, building on all previous versions to deliver the most comprehensive, intelligent, and accurate security testing framework:

| Feature | Description |
|---------|-------------|
| **Adaptive Rate Limiting** | Automatically adjusts request speed based on target responsiveness, avoiding detection and rate-limit blocks. |
| **Cross-Module Vulnerability Correlation** | Correlates findings across different modules to identify attack chains and compound vulnerabilities. |
| **Dynamic Scan Optimization** | Intelligently prioritizes endpoints and payloads based on real-time scan results for maximum efficiency. |
| **SARIF CI/CD Output** | Generates SARIF-format reports for seamless integration with GitHub Code Scanning and other CI/CD pipelines. |
| **Parameter Tampering Detection** | Detects parameter manipulation vulnerabilities including type juggling, mass assignment, and hidden parameter abuse. |
| **Smart Payload Selection** | ML-inspired payload ranking that prioritizes likely-to-succeed payloads based on target technology stack (v8.0). |
| **Attack Chain Correlation** | Maps multi-step attack chains across vulnerability types for realistic exploit path analysis (v8.0). |
| **Bayesian Confidence Scoring** | Bayesian statistical model for data-driven confidence scoring with prior/posterior updating (v8.0). |
| **Response Intelligence** | Deep response analysis detecting WAF blocks, error patterns, and behavioral anomalies (v8.0). |
| **Out-of-Band (OOB) Verification** | DNS and HTTP callback-based confirmation for blind vulnerabilities (v7.0). |
| **Context-Aware Payload Mutation** | Technology-specific and WAF-specific payload generation (v7.0). |
| **WAF Fingerprinting** | Header-based identification of 10 WAF products (v7.0). |
| **Robust Timing Baselines** | Percentile-based timing thresholds eliminating network jitter false positives (v7.0). |
| **Triple-Marker Confirmation** | Three independent markers must ALL trigger the same behavioural change (v4.0). |
| **Cross-Correlation & Entropy Analysis** | Corroborating evidence across parameters with Shannon entropy anomaly detection (v4.0). |
| **Verification Chain** | Every finding includes an ordered audit trail of all verification steps performed. |

### Scan Depth Levels

Control scanning thoroughness with the `--depth` flag:

| Depth | Crawl | Dirs Brute | API Brute | Payloads | Validation | Use Case |
|-------|-------|-----------|-----------|----------|------------|----------|
| `quick` | 1 level, 20 pages | 50 paths | 25 endpoints | 5/type | 1x | Fast surface check |
| `standard` | 2 levels, 50 pages | 100 paths | 50 endpoints | 15/type | 3x | Balanced (default) |
| `deep` | 3 levels, 150 pages | 250 paths | 120 endpoints | 30/type | 5x | Thorough assessment |
| `full` | 5 levels, 500 pages | All paths | All endpoints | All | 7x | Maximum coverage |
| `quantum` | 7 levels, 1000 pages | All paths | All endpoints | All | 10x | Ultra-deep v4.0 — triple confirm, cross-correlation, entropy analysis |
| `titan` | 10 levels, 2000 pages | All paths | All endpoints | All | 15x | Ultimate v7.0 — all quantum + OOB verification, payload mutation, WAF fingerprinting |
| `hydra` | 15 levels, 5000 pages | All paths | All endpoints | All | 20x | Supreme v8.0 — all titan + smart payloads, attack chains, Bayesian scoring, response intelligence |
| `chimera` | 20 levels, 10000 pages | All paths | All endpoints | All | 25x | **Apex v9.0** — all hydra + adaptive rate limiting, vulnerability correlation, scan optimization, SARIF output, parameter tampering |

### Expanded Payload & Wordlist Coverage
- **950+ wordlist entries** across 6 categories (directories, API endpoints, subdomains, backup files, hidden params, user agents)
- **800+ payload variations** across 11 vulnerability categories
- Deeper SQLi, XSS, SSRF, SSTI, LFI, and command injection payloads

### Tool Integrations
| Tool | Purpose | Setup |
|------|---------|-------|
| **Nmap** | Port scanning & service detection | Install `nmap`, set `VS_NMAP_ENABLED=true` |
| **OWASP ZAP** | Automated web app scanning | Run ZAP, set `VS_ZAP_ENABLED=true` |
| **Nuclei** | Template-based vulnerability scanning | Install `nuclei`, set `VS_NUCLEI_ENABLED=true` |
| **Shodan** | Passive host intelligence | Set `SHODAN_API_KEY` |
| **NVD/CVE** | CVE enrichment for findings | Set `NVD_API_KEY` |
| **Amass** | Subdomain enumeration | Install `amass`, set `VS_AMASS_ENABLED=true` |
| **Wappalyzer** | Technology fingerprinting | Set `VS_WAPPALYZER_ENABLED=true` |

### Interfaces
- **CLI** (`venom.py`) — Full-featured command line interface
- **Web UI** (`run.py`) — Flask-based dashboard with real-time scan progress

### Reporting
- **HTML** — Professional pentest report with executive summary
- **JSON** — Machine-readable output for CI/CD integration

---

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/hamahasan441-png/VenomStrike.git
cd VenomStrike

# Install dependencies
pip install -r requirements.txt

# Or install with optional tools
pip install -e ".[full]"

# Copy environment config
cp .env.example .env
```

### Docker

```bash
# Build and run
docker compose up -d

# With OWASP ZAP companion
docker compose --profile with-zap up -d
```

### CLI Usage

```bash
# Auto scan (all modules)
python venom.py -u https://target.com --mode auto

# Specific category
python venom.py -u https://target.com --mode injection --threads 20

# Specific module with learning mode
python venom.py -u https://target.com --mode sqli --learn

# Deep scan — more payloads, deeper crawling
python venom.py -u https://target.com --mode auto --depth deep

# Full scan — maximum coverage, all payloads
python venom.py -u https://target.com --mode auto --depth full --threads 50

# Quantum scan — ultra-deep v4.0 with triple confirmation & cross-correlation
python venom.py -u https://target.com --mode auto --depth quantum --threads 50

# Titan scan — ultimate v7.0 with OOB verification, payload mutation, WAF fingerprinting
python venom.py -u https://target.com --mode auto --depth titan --threads 50

# Hydra scan — supreme v8.0 with smart payloads, attack chains, Bayesian scoring
python venom.py -u https://target.com --mode auto --depth hydra --threads 50

# Chimera scan — apex v9.0 with adaptive rate limiting, vulnerability correlation, SARIF output
python venom.py -u https://target.com --mode auto --depth chimera --threads 50

# With tool integrations
python venom.py -u https://target.com --mode auto --nmap --nuclei

# Full scan with all integrations
python venom.py -u https://target.com --mode auto --nmap --nuclei --cve-enrich

# With proxy through ZAP
python venom.py -u https://target.com --mode auto --zap --proxy http://127.0.0.1:8080
```

### Web UI

```bash
python run.py
# Open http://127.0.0.1:5000
```

---

## Configuration

All settings can be configured via environment variables or `.env` file:

```bash
# Core settings
VS_THREADS=10          # Concurrent threads
VS_TIMEOUT=10          # Request timeout (seconds)
VS_MIN_CONFIDENCE=70   # Minimum confidence to report (0-100)
VS_SCAN_DEPTH=standard # Scan depth: quick, standard, deep, full, quantum, titan, hydra, chimera

# Chimera v9.0 settings
VS_ADAPTIVE_RATE_LIMIT=true                   # Adaptive rate limiting
VS_VULN_CORRELATION=true                      # Cross-module vulnerability correlation
VS_SCAN_OPTIMIZATION=true                     # Dynamic scan optimization
VS_SARIF_OUTPUT=false                         # SARIF CI/CD output
VS_PARAM_TAMPERING=true                       # Parameter tampering detection

# Hydra v8.0 settings
VS_SMART_PAYLOAD=true                         # Smart payload selection
VS_ATTACK_CHAIN=true                          # Attack chain correlation
VS_BAYESIAN_SCORING=true                      # Bayesian confidence scoring
VS_RESPONSE_INTELLIGENCE=true                 # Response intelligence

# Titan v7.0 settings
VS_OOB_CALLBACK_DOMAIN=callback.example.com  # OOB callback domain
VS_PAYLOAD_MUTATION=true                      # Context-aware payload mutation
VS_ROBUST_TIMING=true                         # Percentile-based timing baselines
VS_WAF_FINGERPRINT=true                       # WAF header fingerprinting

# Integrations
VS_NMAP_ENABLED=true
VS_ZAP_ENABLED=true
VS_NUCLEI_ENABLED=true
SHODAN_API_KEY=your-key
NVD_API_KEY=your-key
```

See [`.env.example`](.env.example) for all options.

---

## Architecture

```
VenomStrike/
├── venom.py              # CLI entry point
├── app.py                # Flask web application
├── run.py                # Web UI launcher
├── config.py             # Global configuration
├── core/                 # Framework core
│   ├── engine.py         # Scan orchestrator
│   ├── session.py        # HTTP session management
│   ├── database.py       # SQLite persistence
│   ├── reporter.py       # Report generation
│   ├── validator.py      # Result validation + robust timing
│   ├── oob_verifier.py   # Out-of-Band verification
│   ├── payload_mutator.py # Context-aware payload mutation
│   ├── waf_evasion.py    # WAF detection + fingerprinting
│   ├── rate_limiter.py   # Adaptive rate limiting (v9.0)
│   ├── vulnerability_correlator.py # Cross-module correlation (v9.0)
│   ├── scan_optimizer.py # Dynamic scan optimization (v9.0)
│   ├── sarif_reporter.py # SARIF CI/CD output (v9.0)
│   ├── smart_selector.py # Smart payload selection (v8.0)
│   ├── attack_chain.py   # Attack chain correlation (v8.0)
│   ├── bayesian_scorer.py # Bayesian confidence scoring (v8.0)
│   ├── response_intelligence.py # Response intelligence (v8.0)
│   └── ...
├── exploits/             # 35+ vulnerability modules
│   ├── injection/        # SQLi, NoSQL, Command, SSTI, XXE, LDAP, XPath
│   ├── client_side/      # XSS, CSRF, Clickjacking, CORS, Open Redirect
│   ├── server_side/      # SSRF, LFI, RFI, File Upload, RCE
│   ├── auth/             # Auth Bypass, JWT, Session, OAuth, IDOR
│   ├── logic/            # Race Condition, Business Logic, Mass Assignment
│   └── advanced/         # GraphQL, WebSocket, Cache Poison, CRLF
├── integrations/         # External tool wrappers
│   ├── nmap_scanner.py   # Nmap port scanning
│   ├── nuclei_runner.py  # Nuclei template scanning
│   ├── zap_scanner.py    # OWASP ZAP API
│   ├── shodan_recon.py   # Shodan intelligence
│   ├── cve_lookup.py     # NVD/CVE enrichment
│   ├── amass_enum.py     # Subdomain enumeration
│   └── wappalyzer_fingerprint.py # Technology fingerprinting
├── recon/                # Reconnaissance modules
├── debugger/             # Learning & remediation
├── payloads/             # Payload wordlists
├── wordlists/            # Directory/API wordlists
├── templates/            # Flask HTML templates
├── static/               # CSS & JavaScript
├── tests/                # Test suite (501 tests)
├── Dockerfile            # Container build
├── docker-compose.yml    # Container orchestration
└── pyproject.toml        # Python packaging
```

---

## Scan Modes

| Mode | Description |
|------|-------------|
| `auto` | Full scan with all modules |
| `injection` | SQL, NoSQL, Command, SSTI, XXE, LDAP, XPath injection |
| `client_side` | XSS, CSRF, Clickjacking, CORS, Open Redirect |
| `server_side` | SSRF, LFI, RFI, File Upload, RCE |
| `auth` | Auth Bypass, JWT, Session, OAuth, IDOR |
| `logic` | Race Condition, Business Logic, Mass Assignment |
| `advanced` | GraphQL, WebSocket, Cache Poison, CRLF, Host Header |
| `sqli`, `xss`, etc. | Individual module scan |

---

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests (501 tests)
pytest

# Run linter
ruff check .

# Type checking
mypy core/ integrations/
```

---

## Version History

| Version | Codename | Key Features |
|---------|----------|-------------|
| v9.0 | **Chimera** | Adaptive rate limiting, cross-module vulnerability correlation, dynamic scan optimization, SARIF CI/CD output, parameter tampering |
| v8.0 | Hydra | Smart payload selection, attack chain correlation, Bayesian scoring, response intelligence, adaptive exploitation |
| v7.0 | Titan | OOB verification, payload mutation, WAF fingerprinting, robust timing, input validation |
| v6.0 | Viper | Injection URL, response stability, stricter SSRF |
| v5.0 | Apex | Amass subdomain enum, Wappalyzer fingerprinting |
| v4.0 | Quantum | Triple confirmation, entropy analysis, cross-correlation, statistical confidence |
| v3.0 | — | Expanded payloads/wordlists, scan depth levels |
| v2.0 | — | Tool integrations (Nmap, ZAP, Nuclei, Shodan, CVE) |
| v1.0 | — | Initial release with 35+ modules |

---

## License

MIT — For educational and authorized security testing purposes only.
