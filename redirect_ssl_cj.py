"""
BugHunter AI v2 - Open Redirect Detector (Safe)
"""
import re
from typing import List, Dict
from urllib.parse import urlparse, parse_qs, urlencode
from core.http_client import HttpClient
import config

MODULE_NAME = "OpenRedirectDetector"

# Redirect parameter name patterns
REDIRECT_PARAMS = [
    "redirect", "redirect_to", "redirect_url", "return", "return_to",
    "returnurl", "next", "url", "goto", "target", "destination",
    "forward", "redir", "continue", "location", "back",
]

SAFE_EXTERNAL_URL = "https://example.com"


def analyze_redirect(client: HttpClient, url: str, surface: Dict, mode: str = config.MODE_PASSIVE, **kwargs) -> List[Dict]:
    findings = []

    if mode != config.MODE_ACTIVE:
        # Passive: detect redirect params in URLs
        for page_url in list(surface.get("pages", []))[:30]:
            parsed = urlparse(page_url)
            params = parse_qs(parsed.query)
            for param in params:
                if param.lower() in REDIRECT_PARAMS:
                    findings.append({
                        "module":      MODULE_NAME,
                        "title":       f"Redirect Parameter Detected: '{param}'",
                        "risk":        config.RISK_LOW,
                        "url":         page_url,
                        "description": f"URL parameter '{param}' is a common redirect parameter. "
                                       "If unvalidated, it may enable open redirect attacks used in phishing.",
                        "evidence":    f"URL: {page_url}, Parameter: {param}",
                        "remedy":      "Validate redirect targets against an allowlist of internal paths. "
                                       "Never accept fully qualified URLs in redirect parameters without strict validation.",
                        "confidence":  55,
                        "num_signals": 1,
                    })
        return findings

    # Active: test with safe external URL
    for page_url in list(surface.get("pages", []))[:20]:
        parsed = urlparse(page_url)
        params = parse_qs(parsed.query)

        for param in list(params.keys())[:5]:
            if param.lower() not in REDIRECT_PARAMS:
                continue

            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = SAFE_EXTERNAL_URL

            resp = client.get(page_url.split("?")[0], params=test_params, follow_redirects=False)

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if SAFE_EXTERNAL_URL in location or "example.com" in location:
                    findings.append({
                        "module":      MODULE_NAME,
                        "title":       f"Open Redirect Confirmed: Parameter '{param}'",
                        "risk":        config.RISK_MEDIUM,
                        "url":         page_url,
                        "description": f"Parameter '{param}' accepts and follows external redirect URLs without validation. "
                                       "This allows phishing attacks using trusted domain URLs.",
                        "evidence":    f"Probe: {SAFE_EXTERNAL_URL} → Location: {location}",
                        "remedy":      "Implement strict redirect validation: only allow relative paths or an explicit allowlist.",
                        "confidence":  92,
                        "num_signals": 3,
                    })
                    break

    return findings


# ─── SSL/TLS Analyzer ─────────────────────────────────────────────────────────
"""BugHunter AI v2 - SSL/TLS Analyzer"""
import ssl
import socket
from datetime import datetime
from typing import List, Dict
from core.http_client import HttpClient
import config

MODULE_NAME_SSL = "SSLAnalyzer"


def analyze_ssl(client: HttpClient, url: str, surface: Dict, **kwargs) -> List[Dict]:
    findings = []

    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname
    port     = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        findings.append({
            "module":      MODULE_NAME_SSL,
            "title":       "Site Not Using HTTPS",
            "risk":        config.RISK_CRITICAL,
            "url":         url,
            "description": "The target is served over HTTP without TLS. All data in transit, "
                           "including credentials and session tokens, is exposed to network attackers.",
            "evidence":    f"URL scheme: http://",
            "remedy":      "Obtain a TLS certificate (free via Let's Encrypt) and redirect all HTTP to HTTPS.",
            "confidence":  99,
            "num_signals": 4,
        })
        return findings

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert     = ssock.getpeercert()
                protocol = ssock.version()
                cipher   = ssock.cipher()

        # Protocol version check
        if protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append({
                "module":      MODULE_NAME_SSL,
                "title":       f"Weak TLS Protocol: {protocol}",
                "risk":        config.RISK_HIGH,
                "url":         url,
                "description": f"The server negotiated {protocol} which is deprecated and contains known "
                               "cryptographic weaknesses (BEAST, POODLE, DROWN attacks).",
                "evidence":    f"Negotiated protocol: {protocol}",
                "remedy":      "Disable TLS 1.0 and 1.1. Configure minimum TLS 1.2, prefer TLS 1.3.",
                "confidence":  90,
                "num_signals": 3,
            })

        # Cipher suite check
        if cipher:
            cipher_name = cipher[0]
            if any(weak in cipher_name.upper() for weak in config.WEAK_CIPHERS):
                findings.append({
                    "module":      MODULE_NAME_SSL,
                    "title":       f"Weak Cipher Suite: {cipher_name}",
                    "risk":        config.RISK_HIGH,
                    "url":         url,
                    "description": f"Server is using weak cipher suite '{cipher_name}'. "
                                   "This cipher provides inadequate security against modern attacks.",
                    "evidence":    f"Cipher: {cipher_name}, Protocol: {protocol}, Bits: {cipher[2]}",
                    "remedy":      "Configure server to use only strong cipher suites: "
                                   "ECDHE+AESGCM, ECDHE+CHACHA20, DHE+AESGCM.",
                    "confidence":  88,
                    "num_signals": 3,
                })

        # Certificate expiry
        if cert:
            not_after = cert.get("notAfter", "")
            if not_after:
                try:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.utcnow()).days
                    if days_left < 0:
                        findings.append({
                            "module":      MODULE_NAME_SSL,
                            "title":       "SSL Certificate Expired",
                            "risk":        config.RISK_CRITICAL,
                            "url":         url,
                            "description": f"SSL certificate expired {abs(days_left)} days ago. "
                                           "Browsers will show security warnings and refuse connections.",
                            "evidence":    f"Certificate expired: {not_after}",
                            "remedy":      "Renew the SSL certificate immediately.",
                            "confidence":  99,
                            "num_signals": 4,
                        })
                    elif days_left < 30:
                        findings.append({
                            "module":      MODULE_NAME_SSL,
                            "title":       f"SSL Certificate Expiring Soon ({days_left} days)",
                            "risk":        config.RISK_MEDIUM,
                            "url":         url,
                            "description": f"SSL certificate expires in {days_left} days. "
                                           "Expired certificates cause outages and browser warnings.",
                            "evidence":    f"Certificate expires: {not_after}",
                            "remedy":      "Renew the certificate before expiry. Consider Let's Encrypt auto-renewal.",
                            "confidence":  99,
                            "num_signals": 2,
                        })
                except ValueError:
                    pass

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "module":      MODULE_NAME_SSL,
            "title":       "SSL Certificate Validation Failed",
            "risk":        config.RISK_HIGH,
            "url":         url,
            "description": f"SSL certificate failed verification: {str(e)[:200]}. "
                           "Self-signed or misconfigured certificates enable MITM attacks.",
            "evidence":    f"SSL Error: {str(e)[:200]}",
            "remedy":      "Use a certificate from a trusted CA. Ensure the CN/SAN matches the domain.",
            "confidence":  92,
            "num_signals": 3,
        })
    except Exception as e:
        pass  # SSL connection failure not actionable without more info

    return findings


# ─── Clickjacking Detector ────────────────────────────────────────────────────
"""BugHunter AI v2 - Clickjacking Detector"""

MODULE_NAME_CJ = "ClickjackingDetector"


def analyze_clickjacking(client: HttpClient, url: str, surface: Dict, **kwargs) -> List[Dict]:
    findings = []

    resp = client.get(url)
    if not resp.ok:
        return findings

    headers = {k.lower(): v for k, v in resp.headers.items()}
    xfo     = headers.get("x-frame-options", "")
    csp     = headers.get("content-security-policy", "")

    has_xfo           = bool(xfo)
    has_frame_ancestor = "frame-ancestors" in csp.lower()

    if not has_xfo and not has_frame_ancestor:
        findings.append({
            "module":      MODULE_NAME_CJ,
            "title":       "Clickjacking Protection Missing",
            "risk":        config.RISK_MEDIUM,
            "url":         url,
            "description": "Neither X-Frame-Options nor CSP frame-ancestors is set. "
                           "The page can be embedded in an attacker-controlled iframe, enabling clickjacking attacks.",
            "evidence":    "X-Frame-Options: absent, CSP frame-ancestors: absent",
            "remedy":      "Add X-Frame-Options: DENY (or SAMEORIGIN). Better: use CSP frame-ancestors 'none'.",
            "confidence":  90,
            "num_signals": 2,
        })
    elif xfo.upper() == "ALLOW-FROM":
        findings.append({
            "module":      MODULE_NAME_CJ,
            "title":       "Weak X-Frame-Options: ALLOW-FROM",
            "risk":        config.RISK_LOW,
            "url":         url,
            "description": "X-Frame-Options: ALLOW-FROM is deprecated and unsupported in most modern browsers. "
                           "Use CSP frame-ancestors instead.",
            "evidence":    f"X-Frame-Options: {xfo}",
            "remedy":      "Replace with: Content-Security-Policy: frame-ancestors 'none' or 'self'.",
            "confidence":  80,
            "num_signals": 1,
        })

    return findings
