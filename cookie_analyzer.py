"""
BugHunter AI v2 - Cookie Security Analyzer
Checks for missing Secure, HttpOnly, SameSite flags and session fixation indicators.
"""
import re
from typing import List, Dict
from core.http_client import HttpClient
import config

MODULE_NAME = "CookieAnalyzer"

# Session-like cookie name patterns
SESSION_COOKIE_PATTERNS = [
    r"sess", r"session", r"auth", r"token", r"jwt", r"login",
    r"user", r"uid", r"sid", r"csrf", r"remember", r"access",
]


def analyze(client: HttpClient, url: str, surface: Dict, **kwargs) -> List[Dict]:
    findings = []

    resp = client.get(url)
    if not resp.ok:
        return findings

    cookies = surface.get("cookies", {})

    if not cookies:
        return findings

    for name, attrs in cookies.items():
        is_session = any(re.search(p, name, re.I) for p in SESSION_COOKIE_PATTERNS)
        severity   = config.RISK_HIGH if is_session else config.RISK_MEDIUM

        # Missing Secure flag
        if attrs.get("secure") is False or attrs.get("secure") is None:
            if url.startswith("https"):
                findings.append(_finding(
                    title       = f"Cookie Missing Secure Flag: '{name}'",
                    risk        = severity,
                    url         = url,
                    description = f"Cookie '{name}' is served over HTTPS but lacks the 'Secure' flag. "
                                  "It may be transmitted over HTTP connections, exposing it to interception.",
                    evidence    = f"Set-Cookie: {name}=...; [Secure flag absent]",
                    remedy      = f"Add 'Secure' flag to all cookies: Set-Cookie: {name}=...; Secure; ...",
                    confidence  = 90,
                ))

        # Missing HttpOnly flag
        if attrs.get("httponly") is False or attrs.get("httponly") is None:
            if is_session:
                findings.append(_finding(
                    title       = f"Session Cookie Missing HttpOnly Flag: '{name}'",
                    risk        = config.RISK_HIGH,
                    url         = url,
                    description = f"Session cookie '{name}' lacks the 'HttpOnly' flag, making it accessible "
                                  "to JavaScript. If XSS exists, this cookie can be stolen via document.cookie.",
                    evidence    = f"Set-Cookie: {name}=...; [HttpOnly flag absent]",
                    remedy      = f"Add 'HttpOnly' flag: Set-Cookie: {name}=...; HttpOnly; ...",
                    confidence  = 88,
                ))

        # Missing/Weak SameSite
        samesite = attrs.get("samesite")
        if samesite is None:
            findings.append(_finding(
                title       = f"Cookie Missing SameSite Attribute: '{name}'",
                risk        = config.RISK_MEDIUM,
                url         = url,
                description = f"Cookie '{name}' has no SameSite attribute. Browsers may default to 'Lax', "
                              "but an explicit value should be set. Without 'Strict' or 'Lax', the cookie "
                              "may be sent on cross-origin requests, enabling CSRF.",
                evidence    = f"Set-Cookie: {name}=...; [SameSite absent]",
                remedy      = f"Add SameSite=Strict (or Lax for OAuth flows): "
                              f"Set-Cookie: {name}=...; SameSite=Strict; ...",
                confidence  = 75,
            ))
        elif samesite.lower() == "none":
            if attrs.get("secure"):
                findings.append(_finding(
                    title       = f"Cookie SameSite=None Configured: '{name}'",
                    risk        = config.RISK_MEDIUM,
                    url         = url,
                    description = f"Cookie '{name}' uses SameSite=None, which allows cross-site requests. "
                                  "This is appropriate only for third-party contexts and increases CSRF risk.",
                    evidence    = f"Set-Cookie: {name}=...; SameSite=None; Secure",
                    remedy      = "Use SameSite=Strict or SameSite=Lax unless cross-site access is required.",
                    confidence  = 70,
                ))

    # ── Session Fixation Check ────────────────────────────────────────────────
    # If a session cookie is set BEFORE login (on a non-authenticated page), it may be fixable
    for name in cookies:
        if re.search(r'session|sess|sid', name, re.I):
            findings.append(_finding(
                title       = f"Session Cookie Set on Unauthenticated Page: '{name}'",
                risk        = config.RISK_MEDIUM,
                url         = url,
                description = f"Session cookie '{name}' is issued before authentication. If the same "
                              "session ID is retained after login, this enables session fixation attacks.",
                evidence    = f"Cookie '{name}' present on: {url}",
                remedy      = "Regenerate session identifiers on authentication (session.regenerate_id()). "
                              "Invalidate old session before issuing new credentials.",
                confidence  = 60,
            ))
            break  # One finding for session fixation is enough

    return findings


def _finding(title, risk, url, description, evidence, remedy, confidence=80) -> Dict:
    return {"module": MODULE_NAME, "title": title, "risk": risk, "url": url,
            "description": description, "evidence": evidence, "remedy": remedy,
            "confidence": confidence, "num_signals": 2}
