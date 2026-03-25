"""
BugHunter AI v2 - Technology Fingerprinting Module
Identifies technologies, frameworks, CMS versions, and associated CVE risk.
"""

import re
from typing import List, Dict
from core.http_client import HttpClient
import config

MODULE_NAME = "TechFingerprint"


# Known version-disclosure patterns per technology
VERSION_PATTERNS = {
    "WordPress":    [r'wp-includes/js/[^?]+\?ver=([\d.]+)', r'/wp-content/themes/[^/]+/style\.css\?ver=([\d.]+)'],
    "Drupal":       [r'Drupal\s+([\d.]+)', r'"version":\s*"([\d.]+)".*drupal'],
    "Joomla":       [r'Joomla!\s+([\d.]+)', r'/media/jui/js/jquery\.min\.js\?v=([\d.]+)'],
    "Bootstrap":    [r'bootstrap[^/]*/?([\d.]+)/'],
    "jQuery":       [r'jquery[.-]([\d.]+)(?:\.min)?\.js'],
    "Next.js":      [r'"version":\s*"([\d.]+)".*next'],
    "React":        [r'react@([\d.]+)', r'react\.([\d.]+)\.js'],
    "Angular":      [r'ng-version="([\d.]+)"', r'angular[./]([\d.]+)'],
}

# Technologies with known end-of-life or high-risk versions
EOL_VERSIONS = {
    "WordPress": {"risk": "HIGH",    "eol_before": "6.0",   "note": "Regularly targeted by mass exploitation"},
    "Drupal":    {"risk": "HIGH",    "eol_before": "9.0",   "note": "Drupalgeddon vulnerabilities in older versions"},
    "Joomla":    {"risk": "HIGH",    "eol_before": "4.0",   "note": "Multiple critical RCE in older versions"},
    "jQuery":    {"risk": "MEDIUM",  "eol_before": "3.0",   "note": "Prototype pollution and XSS in < 3.0"},
}

# Admin panel path indicators
ADMIN_PATHS = [
    "/wp-admin", "/wp-login.php", "/administrator", "/admin",
    "/user/login", "/users/sign_in", "/manager", "/cpanel",
    "/phpmyadmin", "/pma", "/adminer", "/phpinfo.php",
]

# Exposed file paths that should never be public
EXPOSED_PATHS = [
    "/.env", "/.git/config", "/config.php", "/wp-config.php",
    "/database.yml", "/settings.py", "/application.properties",
    "/composer.json", "/package.json", "/.htaccess",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/.well-known/security.txt", "/security.txt",
    "/phpinfo.php", "/info.php", "/test.php",
    "/swagger.json", "/openapi.json", "/api/swagger.json",
    "/actuator", "/actuator/health", "/actuator/env",
    "/.well-known/assetlinks.json", "/manifest.json",
]


def analyze(client: HttpClient, url: str, surface: Dict, **kwargs) -> List[Dict]:
    findings = []

    # Get base page response
    resp = client.get(url)
    if not resp.ok:
        return findings

    html    = resp.text
    headers = {k.lower(): v for k, v in resp.headers.items()}

    # ── Technology Detection ──────────────────────────────────────────────────
    detected_techs = set()
    for tech, signatures in config.TECH_SIGNATURES.items():
        if any(sig.lower() in html.lower() or sig.lower() in str(headers).lower()
               for sig in signatures):
            detected_techs.add(tech)

    # ── Version Extraction ────────────────────────────────────────────────────
    versions: Dict[str, str] = {}
    for tech, patterns in VERSION_PATTERNS.items():
        if tech in detected_techs:
            for pattern in patterns:
                m = re.search(pattern, html, re.I)
                if m:
                    versions[tech] = m.group(1)
                    break

    # ── Version Disclosure Findings ───────────────────────────────────────────
    for tech, version in versions.items():
        findings.append({
            "module":      MODULE_NAME,
            "title":       f"Version Disclosure: {tech} {version}",
            "risk":        config.RISK_LOW,
            "url":         url,
            "description": f"Detected {tech} version {version} from page source/headers. "
                           "Version disclosure allows attackers to identify known CVEs for this exact version.",
            "evidence":    f"Technology: {tech}, Version: {version}",
            "remedy":      f"Remove version identifiers from public responses. Use asset fingerprinting without version numbers.",
            "confidence":  88,
            "num_signals": 1,
        })

        # Check EOL risk
        if tech in EOL_VERSIONS:
            eol_info = EOL_VERSIONS[tech]
            findings.append({
                "module":      MODULE_NAME,
                "title":       f"Potentially Outdated Component: {tech} {version}",
                "risk":        eol_info["risk"],
                "url":         url,
                "description": f"{tech} v{version} may be outdated. {eol_info['note']}. "
                               "Older versions have known, actively exploited vulnerabilities.",
                "evidence":    f"{tech} version: {version}",
                "remedy":      f"Update {tech} to the latest stable release and subscribe to security advisories.",
                "confidence":  72,
                "num_signals": 2,
            })

    # ── Admin Panel Detection ─────────────────────────────────────────────────
    for path in ADMIN_PATHS:
        admin_url = url.rstrip("/") + path
        admin_resp = client.head(admin_url)
        if admin_resp.status_code in (200, 301, 302, 403):
            risk = config.RISK_HIGH if admin_resp.status_code in (200, 302) else config.RISK_MEDIUM
            findings.append({
                "module":      MODULE_NAME,
                "title":       f"Admin Panel Exposed: {path}",
                "risk":        risk,
                "url":         admin_url,
                "description": f"Admin/management interface found at '{path}' (HTTP {admin_resp.status_code}). "
                               "Publicly accessible admin panels are prime targets for brute-force and "
                               "credential stuffing attacks.",
                "evidence":    f"GET {admin_url} → {admin_resp.status_code}",
                "remedy":      "Restrict access to admin interfaces via IP allowlisting, VPN, or remove from public web.",
                "confidence":  85,
                "num_signals": 2,
            })

    # ── Sensitive File Exposure ───────────────────────────────────────────────
    for path in EXPOSED_PATHS:
        file_url  = url.rstrip("/") + path
        file_resp = client.get(file_url)

        if file_resp.status_code == 200 and len(file_resp.text) > 10:
            risk        = _assess_exposed_file_risk(path, file_resp.text)
            findings.append({
                "module":      MODULE_NAME,
                "title":       f"Sensitive File Exposed: {path}",
                "risk":        risk,
                "url":         file_url,
                "description": f"The file '{path}' is publicly accessible and returns content. "
                               "This file may contain sensitive configuration, credentials, or system information.",
                "evidence":    f"HTTP 200, Content-Length: {len(file_resp.text)} bytes, "
                               f"Preview: {file_resp.text[:100].strip()}...",
                "remedy":      f"Restrict access to '{path}' via server configuration (deny in .htaccess / nginx). "
                               "Move sensitive files outside the web root.",
                "confidence":  90,
                "num_signals": 3,
            })

    # ── GraphQL Introspection ─────────────────────────────────────────────────
    if "GraphQL" in detected_techs or any("/graphql" in u for u in surface.get("api_endpoints", [])):
        gql_url = url.rstrip("/") + "/graphql"
        gql_resp = client.post(
            gql_url,
            json={"query": "{ __typename }"},
            headers={"Content-Type": "application/json"},
        )
        if gql_resp.status_code == 200 and "__typename" in gql_resp.text:
            # Test for full introspection
            introspect_resp = client.post(
                gql_url,
                json={"query": "{ __schema { types { name } } }"},
                headers={"Content-Type": "application/json"},
            )
            if "__schema" in introspect_resp.text:
                findings.append({
                    "module":      MODULE_NAME,
                    "title":       "GraphQL Introspection Enabled in Production",
                    "risk":        config.RISK_MEDIUM,
                    "url":         gql_url,
                    "description": "GraphQL introspection is enabled, revealing the full schema, all types, "
                                   "queries, mutations, and field names. This significantly aids attackers in "
                                   "mapping the API attack surface.",
                    "evidence":    "POST /graphql with {__schema{types{name}}} returned schema data.",
                    "remedy":      "Disable introspection in production. Add depth limiting and query cost analysis.",
                    "confidence":  95,
                    "num_signals": 3,
                })

    return findings


def _assess_exposed_file_risk(path: str, content: str) -> str:
    """Assign risk level based on file type and content analysis."""
    critical_paths  = ["/.env", "/wp-config.php", "/config.php", "/.git/config",
                       "/database.yml", "/settings.py", "/application.properties"]
    high_paths      = ["/phpinfo.php", "/info.php", "/actuator/env"]

    if any(path.endswith(p) or path == p for p in critical_paths):
        return config.RISK_CRITICAL

    if any(path.endswith(p) or path == p for p in high_paths):
        return config.RISK_HIGH

    # Check content for secrets
    for pattern in config.SENSITIVE_PATTERNS.values():
        if re.search(pattern, content, re.I):
            return config.RISK_CRITICAL

    return config.RISK_MEDIUM
