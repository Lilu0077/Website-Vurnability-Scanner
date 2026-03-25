# 🔍 BugHunter AI v2

> **AI-Powered Web Security Analysis Platform**  
> Ethical hacking. Authorized targets only.

```
██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██╔══██╗██║   ██║██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██████╔╝██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██╔══██╗██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██████╔╝╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
                        AI v2
```

---

## ⚠️ Legal Disclaimer

**This tool is for authorized security testing only.**  
Only use BugHunter AI v2 on:
- Systems you own
- Systems with **explicit written authorization** (bug bounty programs, CTF challenges)

Unauthorized scanning is illegal under the CFAA, Computer Misuse Act, and similar laws worldwide.

---

## 🚀 Installation Guide

### Prerequisites
- Python 3.9+
- pip

### Step 1: Clone / Extract
```bash
git clone https://github.com/yourname/bughunter-ai-v2
cd bughunter_ai_v2
```

### Step 2: Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate.bat       # Windows
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: (Optional) Enable Claude AI Engine
```bash
export ANTHROPIC_API_KEY="sk-ant-your-key-here"
```
Without this, BugHunter uses the built-in local heuristic engine.  
With it, findings are enriched by Claude's expert security reasoning.

### Step 5: Verify Installation
```bash
python main.py --help
```

---

## 📖 Usage

### Basic — Passive Scan (Default, Safest)
```bash
python main.py https://example.com
```

### Active Scan — Safe Probing Mode
```bash
python main.py https://example.com --mode active
```

### Full Options
```bash
python main.py https://target.com \
  --mode active \
  --max-pages 200 \
  --max-depth 5 \
  --delay 1.0 \
  --timeout 20 \
  --output json,html,markdown \
  --output-dir ./reports
```

### With Burp Suite Proxy
```bash
python main.py https://target.com \
  --proxy http://127.0.0.1:8080 \
  --no-verify-ssl
```

### Quiet Mode (Summary Only)
```bash
python main.py https://target.com --quiet
```

### All CLI Options
| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | `passive` | `passive` (analysis only) or `active` (safe probing) |
| `--max-pages` | `100` | Maximum pages to crawl |
| `--max-depth` | `4` | Maximum crawl depth |
| `--delay` | `0.5` | Seconds between requests (be polite!) |
| `--timeout` | `15` | HTTP request timeout |
| `--no-verify-ssl` | off | Disable SSL verification |
| `--proxy` | None | Proxy URL (Burp, ZAP, etc.) |
| `--output` | `json,html,markdown` | Report format(s) |
| `--output-dir` | `output/reports` | Report directory |
| `--no-confirm` | off | Skip authorization prompt |
| `--quiet` | off | Minimal terminal output |

---

## 🏗️ Architecture

```
bughunter_ai_v2/
│
├── main.py                     # 🚀 CLI entry point
├── config.py                   # ⚙  Global configuration & signatures
├── requirements.txt            # 📦 Dependencies
│
├── core/                       # 🧠 Core engine
│   ├── orchestrator.py         #    Central coordinator (adaptive strategy)
│   ├── crawler.py              #    Intelligent attack surface crawler
│   ├── http_client.py          #    Safe, rate-limited HTTP client
│   ├── ai_engine.py            #    AI reasoning (Claude API + local heuristics)
│   └── risk_scorer.py          #    Dynamic risk scoring engine
│
├── modules/                    # 🔍 Detection modules (10 modules, 25+ checks)
│   ├── header_analyzer.py      #    Security headers deep analysis
│   ├── tech_fingerprint.py     #    Technology & version detection
│   ├── xss_detector.py         #    XSS reflection & DOM sink analysis
│   ├── sqli_detector.py        #    SQL injection error & timing detection
│   ├── cors_analyzer.py        #    CORS misconfiguration detection
│   ├── cookie_analyzer.py      #    Cookie security flags analysis
│   ├── info_disclosure.py      #    Secrets, tokens, error leakage
│   ├── csrf_detector.py        #    CSRF token absence detection
│   ├── api_analyzer.py         #    API security & documentation exposure
│   └── redirect_ssl_cj.py      #    Open redirect, SSL/TLS, clickjacking
│
├── reporting/                  # 📊 Report generation
│   └── report_engine.py        #    JSON + HTML dashboard + Markdown
│
├── ui/                         # 🎨 CLI interface
│   └── cli_output.py           #    Rich terminal UI, hacker-style
│
├── utils/                      # 🛠  Utilities
│   └── logger.py               #    Structured logging
│
└── output/
    └── reports/                # 📁 Generated reports land here
```

---

## 🔍 Detection Modules (25+ Checks)

| Module | Checks | Mode |
|--------|--------|------|
| **Security Headers** | HSTS, CSP, X-Frame-Options, X-Content-Type, Referrer-Policy, Permissions-Policy, Cache-Control | Passive |
| **Tech Fingerprint** | 20+ tech stacks, version disclosure, admin panels (10+ paths), sensitive files (20+ paths), GraphQL introspection | Passive + Active |
| **XSS Detector** | DOM sink analysis (10 patterns), reflection testing, form submission, context classification | Passive + Active |
| **SQLi Detector** | Error-based (5 databases), timing anomalies, form testing | Passive + Active |
| **CORS Analyzer** | Wildcard origin, null origin, credential reflection, method exposure | Passive + Active |
| **Cookie Analyzer** | Secure flag, HttpOnly flag, SameSite attribute, session fixation | Passive |
| **Info Disclosure** | 15+ secret patterns (AWS, JWT, GitHub, Stripe), high-entropy token detection, error messages | Passive |
| **CSRF Detector** | Missing CSRF tokens on state-changing forms, SameSite correlation | Passive |
| **API Analyzer** | Documentation exposure, unauthenticated access, excessive data exposure, error verbosity, HTTP methods | Passive + Active |
| **SSL/TLS** | Certificate expiry, weak protocols, weak ciphers | Passive |
| **Open Redirect** | Parameter detection, redirect following test | Passive + Active |
| **Clickjacking** | X-Frame-Options, CSP frame-ancestors | Passive |

---

## 📊 Sample Terminal Output

```
██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
...
╔══════════════════════════════════════════════════════╗
║         🧠 AI-Powered Web Security Analysis          ║
║     Version 2.0.0  •  Ethical Hacking Only           ║
╚══════════════════════════════════════════════════════╝

┄┄┄ ⚙ SCAN CONFIGURATION ┄┄┄
  ► Target:     https://testphp.vulnweb.com
  ► Mode:       PASSIVE
  ► AI Engine:  Claude API ✓

┄┄┄ CRAWL: Discovering attack surface... ┄┄┄
┄┄┄ ANALYZE: Running 10 detection modules... ┄┄┄
    ✓ Security Headers — [5 finding(s)]
    ✓ Tech Fingerprint — [3 finding(s)]
    ✓ SSL/TLS Analysis — [1 finding(s)]
    ✓ Clickjacking — [1 finding(s)]
    ✓ Information Disclosure — [2 finding(s)]
    ✓ Cookie Security — [2 finding(s)]
    ✓ CORS Analyzer — [0]
    ✓ XSS Detection — [4 finding(s)]
    ✓ SQLi Detection — [3 finding(s)]
    ✓ API Security — [1 finding(s)]

┄┄┄ 🌐 ATTACK SURFACE MAP ┄┄┄
🌐 Attack Surface Map — https://testphp.vulnweb.com
├── 📄 Pages & Endpoints (47)
│   ├── https://testphp.vulnweb.com/
│   ├── https://testphp.vulnweb.com/login.php
│   ├── https://testphp.vulnweb.com/artists.php?artist=1
│   └── ... 44 more
├── 📝 Forms (8)
│   ├── /login.php (POST)
│   └── /search.php (GET)
├── 🔑 Parameters (12)
├── ⚡ API Endpoints (3)
└── 📦 JavaScript Files (4)

┄┄┄ 🔍 FINDINGS ┄┄┄

╭─ 🔴 [CRITICAL] SQL Injection Error Triggered: artist (MySQL) ──────────────╮
│  Module:     SQLiDetector                                                    │
│  URL:        https://testphp.vulnweb.com/artists.php                        │
│  Confidence: 92%                                                             │
│  Detail:     Injecting a single quote into parameter 'artist' triggered a   │
│              MySQL SQL error response...                                     │
│  Evidence:   Probe: ' in artist | Error: You have an error in your SQL       │
│              syntax near '''' at line 1                                      │
│  Fix:        Replace string concatenation with parameterized queries.        │
╰──────────────────────────────────────────────────────────────────────────────╯

╭─ 🔴 [CRITICAL] Sensitive File Exposed: /.env ────────────────────────────────╮
│  Module:     TechFingerprint                                                 │
│  URL:        https://testphp.vulnweb.com/.env                               │
│  Confidence: 90%                                                             │
│  Detail:     The file '/.env' is publicly accessible...                     │
│  Evidence:   HTTP 200, Content-Length: 347 bytes                             │
│  Fix:        Restrict access via server config, move outside web root.       │
╰──────────────────────────────────────────────────────────────────────────────╯

... [additional findings] ...

╭─ ✅ SCAN COMPLETE ─────────────────────────────────────────────────────────────╮
│  Scan Summary — https://testphp.vulnweb.com                                  │
│  ┌──────────┬───────┬──────────────────────────────┐                          │
│  │ Severity │ Count │ Status                       │                          │
│  ├──────────┼───────┼──────────────────────────────┤                          │
│  │ 🔴 CRITICAL │  4  │ Immediate action required   │                          │
│  │ 🟠 HIGH     │  6  │ Fix as soon as possible     │                          │
│  │ 🟡 MEDIUM   │  7  │ Plan remediation            │                          │
│  │ 🟢 LOW      │  5  │ Low priority                │                          │
│  │ 🔵 INFO     │  0  │ —                           │                          │
│  │ TOTAL       │ 22  │ Scan duration: 34.2s        │                          │
│  └──────────┴───────┴──────────────────────────────┘                          │
╰──────────────────────────────────────────────────────────────────────────────╯
```

---

## 📄 Sample JSON Report

```json
{
  "meta": {
    "tool": "BugHunter AI v2",
    "version": "2.0.0",
    "generated": "2025-01-15T14:23:11.432Z",
    "target": "https://testphp.vulnweb.com",
    "mode": "active",
    "duration_s": 34.2,
    "total_requests": 187,
    "overall_risk": "CRITICAL"
  },
  "executive_summary": "Security analysis of testphp.vulnweb.com identified 22 findings representing a CRITICAL risk posture. Stack includes PHP, MySQL, Apache. Immediate attention required for 4 critical issues. 3 compound risk correlations detected that amplify individual findings.",
  "immediate_action": "IMMEDIATE: Address SQL Injection on /artists.php — direct data exfiltration risk.",
  "ai_powered": true,
  "attack_surface": {
    "total_pages": 47,
    "total_forms": 8,
    "total_params": 12,
    "total_apis": 3,
    "technologies": ["PHP", "MySQL", "Apache", "jQuery"]
  },
  "findings": [
    {
      "module": "SQLiDetector",
      "title": "SQL Injection Error Triggered: artist (MySQL)",
      "risk": "CRITICAL",
      "url": "https://testphp.vulnweb.com/artists.php",
      "description": "Injecting a single quote triggered a MySQL error...",
      "evidence": "Probe: ' in parameter 'artist' → MySQL syntax error",
      "remedy": "Use parameterized queries exclusively.",
      "confidence": 92,
      "num_signals": 4,
      "ai_reasoning": "Classic unparameterized query concatenation. MySQL error reveals exact query structure, enabling UNION-based extraction without further probing.",
      "priority_fix": "SELECT * FROM artists WHERE id = ? — bind $artist as parameter type INT"
    }
  ],
  "correlations": [
    {
      "finding_1": "Missing Content Security Policy",
      "finding_2": "Input Reflection Detected",
      "combined_risk": "CRITICAL",
      "reasoning": "Absence of CSP combined with reflected input creates a high-probability XSS attack chain."
    }
  ]
}
```

---

## 🔐 Safety Architecture

```
User Input → Authorization Check → Target Validation
                                          ↓
                              Safe HTTP Client (rate-limited)
                                          ↓
                            Passive Analysis First
                                          ↓
                    Active Mode (SAFE probes only — canary strings,
                    single quotes, boolean comparisons)
                                          ↓
                    NO exploitation • NO data extraction
                    NO destructive writes • NO SLEEP/WAITFOR
```

**Safety guarantees built in:**
- Authorization confirmation required (can't be forgotten)  
- SAFE_MODE constant — never set to False  
- Rate limiting on every request (configurable delay)  
- Active mode uses only canary strings and benign probes  
- No SLEEP/WAITFOR timing payloads  
- No UNION injection, no data extraction  
- No file write attempts  
- Max redirect cap (5)  

---

## 🤖 AI Engine

**With `ANTHROPIC_API_KEY` set (Claude-powered):**
- Expert-level analysis of all findings
- CVE cross-referencing
- Compound risk correlations
- Specific, actionable remediation per finding
- Business-level executive summary

**Without API key (local heuristics):**
- Rule-based correlation engine (4+ compound rules)
- Tech-stack-aware risk adjustment
- Pattern-matched remediation advice
- Confidence adjustment based on technology context
- Full scoring and prioritization

---

## 🚀 Future Improvements

### v2.1 — Planned
- [ ] **Subdomain enumeration** — passive DNS + certificate transparency logs
- [ ] **JWT analyzer** — decode and validate JWT tokens (algorithm confusion, none alg)
- [ ] **Authentication flow analyzer** — detect weak login mechanisms, lockout bypass
- [ ] **Path traversal module** — safe canary-based directory escape detection
- [ ] **SSRF indicators** — detect URL parameters that could trigger server-side requests
- [ ] **GraphQL depth limit testing** — safe query complexity analysis
- [ ] **Rate limiting detection** — measure if endpoints enforce rate limits

### v2.2 — Roadmap
- [ ] **WebSocket analysis** — inspect WS handshake and message security
- [ ] **OAuth 2.0 flow analysis** — detect common OAuth misconfigurations
- [ ] **CSP bypass patterns** — analyze deployed CSPs for known bypasses
- [ ] **Prototype pollution** — detect unsafe object merges in JS
- [ ] **Async/concurrent scanning** — aiohttp for 10x faster crawling
- [ ] **Plugin marketplace** — community-contributed detection modules
- [ ] **CI/CD integration** — GitHub Actions / GitLab CI output formats
- [ ] **Burp Suite extension** — integrate as passive scanner

### v3.0 — Vision
- [ ] **Multi-session AI reasoning** — Claude maintains scan context across sessions
- [ ] **Differential scanning** — compare scans over time, detect new attack surface
- [ ] **WAF fingerprinting** — detect and classify WAF type and bypass opportunities
- [ ] **Browser automation** — Playwright-based JavaScript-heavy app scanning
- [ ] **Mobile API analysis** — Android APK/iOS IPA endpoint extraction

---

## 📚 OWASP Reference Mapping

| Module | OWASP Category |
|--------|---------------|
| SQLi Detector | A03:2021 – Injection |
| XSS Detector | A03:2021 – Injection |
| Header Analyzer | A05:2021 – Security Misconfiguration |
| Tech Fingerprint | A06:2021 – Vulnerable Components |
| Info Disclosure | A02:2021 – Cryptographic Failures |
| Cookie Analyzer | A02:2021 – Cryptographic Failures |
| CSRF Detector | A01:2021 – Broken Access Control |
| CORS Analyzer | A05:2021 – Security Misconfiguration |
| API Analyzer | A01:2021 – Broken Access Control |
| SSL/TLS Analyzer | A02:2021 – Cryptographic Failures |

---

*BugHunter AI v2 — For learning, portfolio, and professional authorized use.*  
*Follow responsible disclosure practices. Respect bug bounty program scopes.*
