"""
BugHunter AI v2 - Global Configuration
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional

# ─── Version ───────────────────────────────────────────────────────────────────
VERSION = "2.0.0"
TOOL_NAME = "BugHunter AI v2"
AUTHOR = "BugHunter AI Security Team"

# ─── Scanning Modes ────────────────────────────────────────────────────────────
MODE_PASSIVE = "passive"
MODE_ACTIVE  = "active"

# ─── Risk Levels ───────────────────────────────────────────────────────────────
RISK_CRITICAL = "CRITICAL"
RISK_HIGH     = "HIGH"
RISK_MEDIUM   = "MEDIUM"
RISK_LOW      = "LOW"
RISK_INFO     = "INFO"

# ─── HTTP Client Defaults ──────────────────────────────────────────────────────
DEFAULT_TIMEOUT        = 15
DEFAULT_MAX_RETRIES    = 2
DEFAULT_DELAY          = 0.5          # seconds between requests
DEFAULT_MAX_PAGES      = 100
DEFAULT_MAX_DEPTH      = 4
DEFAULT_USER_AGENT     = (
    "Mozilla/5.0 (compatible; BugHunterAI/2.0; +https://bughunter.ai/bot)"
)

# ─── AI Engine ─────────────────────────────────────────────────────────────────
ANTHROPIC_API_KEY      = os.getenv("ANTHROPIC_API_KEY", "")
AI_MODEL               = "claude-sonnet-4-20250514"
AI_MAX_TOKENS          = 1500
AI_ENABLED             = bool(ANTHROPIC_API_KEY)

# ─── Output ────────────────────────────────────────────────────────────────────
OUTPUT_DIR             = "output/reports"
REPORT_FORMATS         = ["json", "html", "markdown"]

# ─── Safety Controls ───────────────────────────────────────────────────────────
SAFE_MODE              = True         # NEVER set to False
MAX_ACTIVE_PAYLOADS    = 3            # strict limit on safe probes
REQUIRE_CONFIRMATION   = True

# ─── Safe Canary Tokens (non-destructive probes) ───────────────────────────────
SAFE_CANARY_STRING     = "bughunter_ai_probe_7f3a"
SAFE_NUMERIC_PROBE     = "9999999999"
SAFE_STRING_PROBE      = "bughunter_test_input"

# ─── Technology Signatures ─────────────────────────────────────────────────────
TECH_SIGNATURES = {
    "WordPress":     ["wp-content", "wp-includes", "wp-login.php"],
    "Drupal":        ["sites/default/files", "misc/drupal.js"],
    "Joomla":        ["/administrator/", "Joomla!"],
    "Laravel":       ["laravel_session", "X-Powered-By: PHP"],
    "Django":        ["csrfmiddlewaretoken", "django"],
    "Rails":         ["_rails_session", "Ruby on Rails"],
    "Express.js":    ["X-Powered-By: Express"],
    "ASP.NET":       ["ASP.NET_SessionId", "X-Powered-By: ASP.NET", "__VIEWSTATE"],
    "Next.js":       ["__NEXT_DATA__", "_next/static"],
    "React":         ["__react", "data-reactroot"],
    "Angular":       ["ng-version", "ng-app"],
    "Vue.js":        ["__vue__", "data-v-"],
    "Bootstrap":     ["bootstrap.min.css", "bootstrap.bundle"],
    "jQuery":        ["jquery.min.js", "jquery.js"],
    "Nginx":         ["Server: nginx"],
    "Apache":        ["Server: Apache"],
    "Cloudflare":    ["cf-ray", "cloudflare"],
    "Fastly":        ["X-Served-By", "Fastly"],
    "Varnish":       ["X-Varnish", "Via: varnish"],
    "GraphQL":       ["/graphql", "__typename", "application/graphql"],
    "Swagger":       ["swagger-ui", "swagger.json", "openapi.json"],
}

# ─── Sensitive Info Patterns ───────────────────────────────────────────────────
SENSITIVE_PATTERNS = {
    "aws_key":          r"AKIA[0-9A-Z]{16}",
    "aws_secret":       r"(?i)aws(.{0,20})secret(.{0,20})['\"][0-9a-zA-Z/+]{40}['\"]",
    "jwt_token":        r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    "private_key":      r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    "google_api_key":   r"AIza[0-9A-Za-z-_]{35}",
    "github_token":     r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}",
    "stripe_key":       r"sk_(live|test)_[0-9a-zA-Z]{24,}",
    "db_password":      r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]",
    "internal_ip":      r"(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)",
    "email_address":    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "phone_number":     r"\+?1?\s*\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}",
    "api_key_generic":  r"(?i)(api[_-]?key|api[_-]?token|access[_-]?token)\s*[=:]\s*['\"][a-zA-Z0-9]{16,}['\"]",
    "sql_error":        r"(?i)(sql syntax|mysql_fetch|pg_query|ora-\d{4}|sqlite3|unclosed quotation|syntax error.*sql)",
    "stack_trace":      r"(?i)(traceback|stack trace|exception in thread|at [a-z]+\.[a-z]+\()",
    "php_error":        r"(?i)(fatal error|parse error|warning:|notice:).*php",
    "debug_info":       r"(?i)(debug|development mode|debug mode|verbose)",
}

# ─── Security Headers ──────────────────────────────────────────────────────────
REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security":    "HSTS missing — enables downgrade attacks",
    "Content-Security-Policy":      "CSP missing — opens XSS vectors",
    "X-Frame-Options":              "Clickjacking protection missing",
    "X-Content-Type-Options":       "MIME-sniffing protection missing",
    "Referrer-Policy":              "Referrer leakage possible",
    "Permissions-Policy":           "Feature policy missing",
    "X-XSS-Protection":             "Legacy XSS filter not explicitly set",
}

DANGEROUS_HEADERS = {
    "X-Powered-By":    "Technology disclosure",
    "Server":          "Server version disclosure",
    "X-AspNet-Version":"ASP.NET version disclosure",
    "X-Runtime":       "Framework runtime disclosure",
}

# ─── Cookie Flags ──────────────────────────────────────────────────────────────
REQUIRED_COOKIE_FLAGS = ["Secure", "HttpOnly", "SameSite"]

# ─── CORS Risk Origins ─────────────────────────────────────────────────────────
CORS_RISKY_WILDCARDS = ["*", "null"]

# ─── SSL Weak Configs ──────────────────────────────────────────────────────────
WEAK_SSL_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
WEAK_CIPHERS = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]
