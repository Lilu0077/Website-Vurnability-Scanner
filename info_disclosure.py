"""
BugHunter AI v2 - Information Disclosure Module
Scans HTML, JS, and responses for secrets, API keys, internal data.
"""
import re
from typing import List, Dict
from core.http_client import HttpClient
from core.ai_engine import AIEngine
import config

MODULE_NAME = "InfoDisclosure"


def analyze(client: HttpClient, url: str, surface: Dict, **kwargs) -> List[Dict]:
    findings = []

    # Scan all pages and JS files
    urls_to_scan = list(surface.get("pages", []))[:25] + list(surface.get("js_files", []))[:20]

    for scan_url in urls_to_scan:
        resp = client.get(scan_url)
        if not resp.ok or not resp.text:
            continue

        text = resp.text

        # ── Sensitive Pattern Detection ────────────────────────────────────
        for pattern_name, pattern in config.SENSITIVE_PATTERNS.items():
            matches = list(re.finditer(pattern, text, re.I | re.MULTILINE))
            if not matches:
                continue

            match = matches[0]
            start = max(0, match.start() - 20)
            end   = min(len(text), match.end() + 20)
            snippet = text[start:end].strip()

            # Determine risk by pattern type
            risk = _pattern_risk(pattern_name)

            findings.append({
                "module":      MODULE_NAME,
                "title":       f"Sensitive Data Disclosure: {pattern_name.replace('_', ' ').title()}",
                "risk":        risk,
                "url":         scan_url,
                "description": f"Pattern '{pattern_name}' matched in response. "
                               f"{len(matches)} occurrence(s) found. This may expose credentials, "
                               "tokens, or sensitive system information.",
                "evidence":    f"Pattern: {pattern_name}\nSample: ...{snippet}...",
                "remedy":      _pattern_remedy(pattern_name),
                "confidence":  _pattern_confidence(pattern_name),
                "num_signals": min(len(matches) + 1, 4),
            })

        # ── High-Entropy Token Detection ──────────────────────────────────
        # Find long alphanumeric strings that look like secrets
        for token_match in re.finditer(r'["\']([A-Za-z0-9+/=_\-]{24,64})["\']', text):
            token = token_match.group(1)
            if AIEngine.is_high_entropy(token, threshold=4.2):
                # Verify it's not a common non-secret (like base64 image prefix, etc.)
                if not re.match(r'^(iVBOR|/9j/4|AAAA|data:|http)', token):
                    start = max(0, token_match.start() - 30)
                    end   = min(len(text), token_match.end() + 30)
                    findings.append({
                        "module":      MODULE_NAME,
                        "title":       "High-Entropy Token in Response (Potential Secret)",
                        "risk":        config.RISK_MEDIUM,
                        "url":         scan_url,
                        "description": f"A high-entropy string (likely a secret, API key, or token) "
                                       f"was found in the response. Entropy: {AIEngine.calculate_entropy(token):.2f} bits.",
                        "evidence":    f"...{text[start:end].strip()}...",
                        "remedy":      "Move secrets out of client-facing code. Use environment variables "
                                       "or secrets management systems. Rotate the exposed credential.",
                        "confidence":  65,
                        "num_signals": 2,
                    })
                    break  # One per page to avoid noise

    return _dedup(findings)


def _pattern_risk(pattern_name: str) -> str:
    critical = {"aws_key", "aws_secret", "private_key", "github_token", "stripe_key"}
    high     = {"jwt_token", "google_api_key", "api_key_generic", "db_password"}
    medium   = {"sql_error", "stack_trace", "php_error", "debug_info"}
    if pattern_name in critical: return config.RISK_CRITICAL
    if pattern_name in high:     return config.RISK_HIGH
    if pattern_name in medium:   return config.RISK_MEDIUM
    return config.RISK_LOW


def _pattern_confidence(pattern_name: str) -> int:
    high_conf = {"aws_key", "private_key", "jwt_token", "sql_error", "stack_trace", "php_error"}
    return 90 if pattern_name in high_conf else 72


def _pattern_remedy(pattern_name: str) -> str:
    remedies = {
        "aws_key":       "Revoke the exposed AWS key immediately. Rotate all credentials. Use IAM roles instead of static keys.",
        "jwt_token":     "Rotate the JWT signing secret. Investigate if the token grants unauthorized access.",
        "private_key":   "Revoke the certificate immediately. Regenerate the key pair. Store private keys only in secure vaults.",
        "github_token":  "Revoke the GitHub token immediately at github.com/settings/tokens.",
        "stripe_key":    "Revoke the Stripe API key at dashboard.stripe.com/apikeys immediately.",
        "db_password":   "Rotate database credentials immediately. Audit access logs for unauthorized queries.",
        "sql_error":     "Implement generic error pages. Log detailed errors server-side only. Use parameterized queries.",
        "stack_trace":   "Disable debug/verbose mode in production. Implement generic error handlers.",
        "php_error":     "Set display_errors=Off in php.ini. Use custom error handlers.",
        "debug_info":    "Disable debug mode for production deployments.",
    }
    return remedies.get(pattern_name, "Remove sensitive data from client-facing responses. Review and audit code.")


def _dedup(findings):
    seen, out = set(), []
    for f in findings:
        k = (f["title"], f["url"])
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out
