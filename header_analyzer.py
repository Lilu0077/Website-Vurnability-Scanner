"""
BugHunter AI v2 - Security Headers Analyzer
Deep analysis of HTTP security headers including presence, values, and misconfigurations.
"""

import re
from typing import List, Dict, Any, Optional
from core.http_client import HttpClient, HttpResponse
import config

MODULE_NAME = "HeaderAnalyzer"


def analyze(client: HttpClient, url: str, surface: Dict, **kwargs) -> List[Dict]:
    """
    Analyze security headers from the target URL.
    Returns list of findings.
    """
    findings = []

    resp = client.get(url)
    if not resp.ok:
        return findings

    headers = {k.lower(): v for k, v in resp.headers.items()}

    # ── Missing Required Security Headers ──────────────────────────────────────
    for header, reason in config.REQUIRED_SECURITY_HEADERS.items():
        if header.lower() not in headers:
            findings.append(_make_finding(
                title       = f"Missing Security Header: {header}",
                risk        = _header_risk(header),
                url         = url,
                description = f"{reason}. The header '{header}' was not found in the server response.",
                evidence    = f"Response headers: {list(headers.keys())}",
                remedy      = _header_remedy(header),
                confidence  = 95,
                signals     = 1,
            ))

    # ── Information Disclosure Headers ─────────────────────────────────────────
    for header, desc in config.DANGEROUS_HEADERS.items():
        val = headers.get(header.lower())
        if val:
            findings.append(_make_finding(
                title       = f"Information Disclosure via {header} Header",
                risk        = config.RISK_LOW,
                url         = url,
                description = f"{desc}. Value revealed: '{val}'",
                evidence    = f"{header}: {val}",
                remedy      = f"Remove or mask the '{header}' header in your server/framework configuration.",
                confidence  = 90,
                signals     = 1,
            ))

    # ── HSTS Deep Analysis ──────────────────────────────────────────────────────
    hsts = headers.get("strict-transport-security")
    if hsts:
        findings.extend(_analyze_hsts(hsts, url))

    # ── CSP Deep Analysis ───────────────────────────────────────────────────────
    csp = headers.get("content-security-policy")
    if csp:
        findings.extend(_analyze_csp(csp, url))

    # ── CORS Analysis from Headers ──────────────────────────────────────────────
    acao = headers.get("access-control-allow-origin")
    if acao:
        findings.extend(_analyze_cors_header(acao, url, headers))

    # ── Referrer Policy Analysis ────────────────────────────────────────────────
    ref_policy = headers.get("referrer-policy")
    if ref_policy:
        findings.extend(_analyze_referrer_policy(ref_policy, url))

    # ── Cache Control Analysis ──────────────────────────────────────────────────
    cache = headers.get("cache-control", "")
    pragma = headers.get("pragma", "")
    if not re.search(r'no-store|no-cache|private', cache, re.I) and not re.search(r'no-cache', pragma, re.I):
        # Only flag for pages that look like they require auth
        if any(p in url.lower() for p in ["/account", "/profile", "/dashboard", "/admin", "/user"]):
            findings.append(_make_finding(
                title       = "Sensitive Page Not Protected by Cache-Control",
                risk        = config.RISK_MEDIUM,
                url         = url,
                description = "Authenticated/sensitive page served without cache control directives. "
                              "Browser and proxy caches may store sensitive data.",
                evidence    = f"Cache-Control: {cache or 'absent'}, Pragma: {pragma or 'absent'}",
                remedy      = "Set Cache-Control: no-store, no-cache, private for authenticated pages.",
                confidence  = 65,
                signals     = 1,
            ))

    # ── Feature Policy / Permissions Policy ─────────────────────────────────────
    permissions = headers.get("permissions-policy") or headers.get("feature-policy")
    if not permissions:
        findings.append(_make_finding(
            title       = "Missing Permissions-Policy Header",
            risk        = config.RISK_LOW,
            url         = url,
            description = "No Permissions-Policy header found. Browser features like camera, microphone, "
                          "and geolocation are unrestricted for the page origin.",
            evidence    = "Header absent from response",
            remedy      = "Implement Permissions-Policy: camera=(), microphone=(), geolocation=()",
            confidence  = 80,
            signals     = 1,
        ))

    return findings


# ─── HSTS Analysis ────────────────────────────────────────────────────────────
def _analyze_hsts(hsts_value: str, url: str) -> List[Dict]:
    findings = []
    max_age_match = re.search(r'max-age=(\d+)', hsts_value, re.I)
    max_age = int(max_age_match.group(1)) if max_age_match else 0

    if max_age < 31536000:
        findings.append(_make_finding(
            title       = "HSTS max-age Too Short",
            risk        = config.RISK_LOW,
            url         = url,
            description = f"HSTS max-age is {max_age}s (< 1 year). Short max-age reduces the effectiveness "
                          "of HSTS preloading and leaves a wider window for downgrade attacks.",
            evidence    = f"Strict-Transport-Security: {hsts_value}",
            remedy      = "Set max-age=31536000 (1 year). Add includeSubDomains and preload for maximum coverage.",
            confidence  = 90,
            signals     = 1,
        ))

    if "includesubdomains" not in hsts_value.lower():
        findings.append(_make_finding(
            title       = "HSTS Missing includeSubDomains",
            risk        = config.RISK_LOW,
            url         = url,
            description = "HSTS does not include 'includeSubDomains'. Subdomains are vulnerable to HTTP downgrade "
                          "and can be used as cookie-injection vectors.",
            evidence    = f"Strict-Transport-Security: {hsts_value}",
            remedy      = "Add 'includeSubDomains' to the HSTS header.",
            confidence  = 80,
            signals     = 1,
        ))

    return findings


# ─── CSP Analysis ─────────────────────────────────────────────────────────────
def _analyze_csp(csp_value: str, url: str) -> List[Dict]:
    findings = []

    # Unsafe directives
    if "'unsafe-inline'" in csp_value:
        findings.append(_make_finding(
            title       = "CSP Contains 'unsafe-inline' Directive",
            risk        = config.RISK_MEDIUM,
            url         = url,
            description = "The 'unsafe-inline' CSP directive allows inline JavaScript and CSS execution, "
                          "significantly weakening XSS protection.",
            evidence    = f"Content-Security-Policy: {csp_value[:300]}",
            remedy      = "Remove 'unsafe-inline'. Use nonces or hashes for required inline scripts.",
            confidence  = 92,
            signals     = 2,
        ))

    if "'unsafe-eval'" in csp_value:
        findings.append(_make_finding(
            title       = "CSP Contains 'unsafe-eval' Directive",
            risk        = config.RISK_MEDIUM,
            url         = url,
            description = "The 'unsafe-eval' CSP directive allows dynamic code evaluation (eval, Function(), "
                          "setTimeout with strings), creating XSS escalation paths.",
            evidence    = f"Content-Security-Policy: {csp_value[:300]}",
            remedy      = "Remove 'unsafe-eval'. Refactor code that uses eval() or Function().",
            confidence  = 88,
            signals     = 2,
        ))

    if re.search(r"default-src\s+['\"]?\*['\"]?", csp_value):
        findings.append(_make_finding(
            title       = "CSP default-src Wildcard (*)",
            risk        = config.RISK_HIGH,
            url         = url,
            description = "The CSP uses a wildcard (*) for default-src, allowing resources to be loaded from any origin. "
                          "This effectively nullifies XSS protection.",
            evidence    = f"Content-Security-Policy: {csp_value[:300]}",
            remedy      = "Specify explicit allowed origins instead of wildcard. Start with default-src 'self'.",
            confidence  = 94,
            signals     = 2,
        ))

    # Check for missing frame-ancestors (framing protection)
    if "frame-ancestors" not in csp_value.lower() and "x-frame-options" not in url:
        findings.append(_make_finding(
            title       = "CSP Missing frame-ancestors Directive",
            risk        = config.RISK_LOW,
            url         = url,
            description = "CSP does not define frame-ancestors. Without this, clickjacking "
                          "protection relies solely on X-Frame-Options.",
            evidence    = f"Content-Security-Policy: {csp_value[:200]}",
            remedy      = "Add frame-ancestors 'none' or frame-ancestors 'self' to CSP.",
            confidence  = 70,
            signals     = 1,
        ))

    return findings


# ─── CORS Header Analysis ─────────────────────────────────────────────────────
def _analyze_cors_header(acao: str, url: str, headers: Dict) -> List[Dict]:
    findings = []
    acac = headers.get("access-control-allow-credentials", "")

    if acao == "*":
        findings.append(_make_finding(
            title       = "CORS Wildcard Origin (*) Configured",
            risk        = config.RISK_MEDIUM,
            url         = url,
            description = "Access-Control-Allow-Origin: * allows any origin to make cross-origin requests. "
                          "While credentials cannot be sent with wildcard, it exposes public APIs to cross-origin abuse.",
            evidence    = f"Access-Control-Allow-Origin: {acao}",
            remedy      = "Replace wildcard with explicit allowed origins. Use origin validation for credentialed APIs.",
            confidence  = 85,
            signals     = 1,
        ))

    if acao == "null":
        findings.append(_make_finding(
            title       = "CORS null Origin Allowed",
            risk        = config.RISK_HIGH,
            url         = url,
            description = "Access-Control-Allow-Origin: null trusts the 'null' origin, which is sent by "
                          "sandboxed iframes and local files — a known CORS bypass technique.",
            evidence    = f"Access-Control-Allow-Origin: null",
            remedy      = "Remove null from allowed origins. Never trust the null origin.",
            confidence  = 90,
            signals     = 2,
        ))

    if acac.lower() == "true" and acao != "*":
        findings.append(_make_finding(
            title       = "CORS Allows Credentials with Dynamic Origin",
            risk        = config.RISK_HIGH,
            url         = url,
            description = "CORS is configured to allow credentials (cookies, auth headers) with a non-wildcard origin. "
                          "If the origin is reflected without validation, this enables credential theft from any site.",
            evidence    = f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: true",
            remedy      = "Validate the Origin header against a strict allowlist before reflecting it. "
                          "Never combine ACAO reflection with credentials=true.",
            confidence  = 80,
            signals     = 2,
        ))

    return findings


# ─── Referrer Policy Analysis ─────────────────────────────────────────────────
def _analyze_referrer_policy(policy: str, url: str) -> List[Dict]:
    findings = []
    unsafe_policies = ["unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"]

    if any(p in policy.lower() for p in unsafe_policies):
        findings.append(_make_finding(
            title       = "Weak Referrer-Policy Configuration",
            risk        = config.RISK_LOW,
            url         = url,
            description = f"Referrer-Policy is set to '{policy}', which may leak the full URL (including "
                          "query parameters containing tokens or sensitive data) in the Referer header to third parties.",
            evidence    = f"Referrer-Policy: {policy}",
            remedy      = "Use Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
            confidence  = 75,
            signals     = 1,
        ))

    return findings


# ─── Helpers ──────────────────────────────────────────────────────────────────
def _header_risk(header: str) -> str:
    critical_headers = {"Content-Security-Policy", "Strict-Transport-Security"}
    high_headers     = {"X-Frame-Options"}
    if header in critical_headers: return config.RISK_HIGH
    if header in high_headers:     return config.RISK_MEDIUM
    return config.RISK_LOW


def _header_remedy(header: str) -> str:
    remedies = {
        "Strict-Transport-Security":
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy":
            "Add: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
        "X-Frame-Options":
            "Add: X-Frame-Options: DENY (or SAMEORIGIN if framing within the same origin is needed)",
        "X-Content-Type-Options":
            "Add: X-Content-Type-Options: nosniff",
        "Referrer-Policy":
            "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "Permissions-Policy":
            "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    }
    return remedies.get(header, f"Implement the '{header}' header per OWASP Secure Headers Project guidelines.")


def _make_finding(
    title: str, risk: str, url: str, description: str,
    evidence: str, remedy: str, confidence: int, signals: int
) -> Dict:
    return {
        "module":      MODULE_NAME,
        "title":       title,
        "risk":        risk,
        "url":         url,
        "description": description,
        "evidence":    evidence,
        "remedy":      remedy,
        "confidence":  confidence,
        "num_signals": signals,
    }
