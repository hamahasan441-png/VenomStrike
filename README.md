# 🗡️ VenomStrike v4.0 — Quantum Edition

> **Advanced Security Testing & Vulnerability Debugging Framework — Quantum Edition — Educational Tool**

⚠️ **LEGAL DISCLAIMER**: VenomStrike is for **authorized security testing ONLY**. You must have explicit written permission to test any system. Unauthorized testing is illegal and unethical.

---

## Features

### Core Scanning Engine
- **35+ vulnerability modules** across 6 categories: Injection, Client-Side, Server-Side, Auth, Logic, Advanced
- **Multi-threaded scanning** with configurable concurrency
- **Automatic reconnaissance**: endpoint discovery, tech fingerprinting, attack surface mapping
- **False positive filtering** with multi-stage validation and confidence scoring
- **Learning mode**: fix code, explanations, and OWASP mapping for every finding

### Quantum Verification Engine (v4.0)

VenomStrike v4.0 "Quantum" introduces an enhanced verification pipeline to ensure **all reported vulnerabilities are real and true**:

| Feature | Description |
|---------|-------------|
| **Triple-Marker Confirmation** | Three independent injection markers must ALL trigger the same behavioural change. Baseline must be clean. 25-point confidence boost. |
| **Cross-Correlation Analysis** | Findings of the same vulnerability type across different parameters on the same endpoint provide corroborating evidence, boosting confidence. |
| **Entropy-Based Anomaly Detection** | Measures Shannon entropy delta between baseline and payload responses to detect structural changes (error dumps, file contents) vs cosmetic noise. |
| **Statistical Confidence Scoring** | Uses z-score analysis and p-value significance testing across multiple measurement samples for data-driven confidence instead of threshold guessing. |
| **Verification Chain** | Every finding includes an ordered audit trail of all verification steps performed, with method names, results, and timestamps. |

### Scan Depth Levels

Control scanning thoroughness with the `--depth` flag:

| Depth | Crawl | Dirs Brute | API Brute | Payloads | Validation | Use Case |
|-------|-------|-----------|-----------|----------|------------|----------|
| `quick` | 1 level, 20 pages | 50 paths | 25 endpoints | 5/type | 1x | Fast surface check |
| `standard` | 2 levels, 50 pages | 100 paths | 50 endpoints | 15/type | 3x | Balanced (default) |
| `deep` | 3 levels, 150 pages | 250 paths | 120 endpoints | 30/type | 5x | Thorough assessment |
| `full` | 5 levels, 500 pages | All paths | All endpoints | All | 7x | Maximum coverage |
| `quantum` | 7 levels, 1000 pages | All paths | All endpoints | All | 10x | **Ultra-deep v4.0** — triple confirm, cross-correlation, entropy analysis |

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
VS_SCAN_DEPTH=standard # Scan depth: quick, standard, deep, full, quantum

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
│   ├── validator.py      # Result validation
│   └── ...
├── exploits/             # 35+ vulnerability modules
│   ├── injection/        # SQLi, NoSQL, Command, SSTI, XXE, LDAP, XPath
│   ├── client_side/      # XSS, CSRF, Clickjacking, CORS, Open Redirect
│   ├── server_side/      # SSRF, LFI, RFI, File Upload, RCE
│   ├── auth/             # Auth Bypass, JWT, Session, OAuth, IDOR
│   ├── logic/            # Race Condition, Business Logic, Mass Assignment
│   └── advanced/         # GraphQL, WebSocket, Cache Poison, CRLF
├── integrations/         # External tool wrappers (v2.0)
│   ├── nmap_scanner.py   # Nmap port scanning
│   ├── nuclei_runner.py  # Nuclei template scanning
│   ├── zap_scanner.py    # OWASP ZAP API
│   ├── shodan_recon.py   # Shodan intelligence
│   └── cve_lookup.py     # NVD/CVE enrichment
├── recon/                # Reconnaissance modules
├── debugger/             # Learning & remediation
├── payloads/             # Payload wordlists
├── wordlists/            # Directory/API wordlists
├── templates/            # Flask HTML templates
├── static/               # CSS & JavaScript
├── tests/                # Test suite
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

# Run tests
pytest

# Run linter
ruff check .

# Type checking
mypy core/ integrations/
```

---

## License

MIT — For educational and authorized security testing purposes only.
