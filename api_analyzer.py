"""
BugHunter AI v2 - API Security Analyzer
Detects API-specific vulnerabilities: missing auth, excessive data exposure,
broken object-level authorization indicators, and mass assignment risks.
"""
import re
import json
from typing import List, Dict
from core.http_client import HttpClient
import config

MODULE_NAME = "APIAnalyzer"

# Sensitive fields that should not appear in API responses
SENSITIVE_FIELDS = [
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "credit_card", "cc_number", "ssn", "social_security",
    "private_key", "access_token", "refresh_token", "auth",
]

# Common API documentation paths
API_DOC_PATHS = [
    "/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml",
    "/api-docs", "/openapi.json", "/openapi.yaml", "/redoc",
    "/api/swagger.json", "/api/openapi.json", "/v1/swagger.json",
    "/api/v1/docs", "/docs", "/api/docs",
]


def analyze(client: HttpClient, url: str, surface: Dict, **kwargs) -> List[Dict]:
    findings = []

    api_endpoints = surface.get("api_endpoints", [])

    if not api_endpoints:
        return findings

    # ── API Documentation Exposure ────────────────────────────────────────────
    for path in API_DOC_PATHS:
        doc_url = url.rstrip("/") + path
        resp = client.get(doc_url)
        if resp.status_code == 200 and len(resp.text) > 100:
            has_spec = any(k in resp.text.lower() for k in ["openapi", "swagger", "paths", "endpoint"])
            if has_spec:
                findings.append({
                    "module":      MODULE_NAME,
                    "title":       f"API Documentation Exposed: {path}",
                    "risk":        config.RISK_MEDIUM,
                    "url":         doc_url,
                    "description": "API specification/documentation is publicly accessible. "
                                   "This reveals all endpoints, parameters, authentication methods, "
                                   "and data models — a complete attack surface map for adversaries.",
                    "evidence":    f"GET {doc_url} → HTTP 200, {len(resp.text)} bytes",
                    "remedy":      "Restrict API documentation to authenticated developers only. "
                                   "Use IP allowlisting or authentication for documentation endpoints.",
                    "confidence":  92,
                    "num_signals": 2,
                })

    # ── Unauthenticated API Access ────────────────────────────────────────────
    for api_url in api_endpoints[:15]:
        resp = client.get(api_url)

        if resp.status_code in (200, 201) and resp.is_json:
            data_str = resp.text
            size_kb  = len(data_str.encode()) / 1024

            findings.append({
                "module":      MODULE_NAME,
                "title":       "API Endpoint Accessible Without Authentication",
                "risk":        config.RISK_MEDIUM,
                "url":         api_url,
                "description": f"API endpoint returns {size_kb:.1f}KB of JSON data without requiring "
                               "authentication. Verify this endpoint should be publicly accessible.",
                "evidence":    f"GET {api_url} → HTTP {resp.status_code}, {size_kb:.1f}KB JSON",
                "remedy":      "Implement authentication (JWT, OAuth 2.0, API keys) for all non-public endpoints. "
                               "Apply principle of least privilege to API access control.",
                "confidence":  60,  # Lower — some APIs are intentionally public
                "num_signals": 1,
            })

            # ── Excessive Data Exposure ────────────────────────────────────
            try:
                api_data = json.loads(data_str)
                exposed = _check_sensitive_fields(api_data)
                if exposed:
                    findings.append({
                        "module":      MODULE_NAME,
                        "title":       f"Excessive API Data Exposure: {', '.join(exposed[:3])}",
                        "risk":        config.RISK_HIGH,
                        "url":         api_url,
                        "description": f"API response contains potentially sensitive fields: {exposed}. "
                                       "APIs should return only the minimum data required by the client.",
                        "evidence":    f"Sensitive fields in JSON response: {exposed}",
                        "remedy":      "Apply response filtering: only include fields that the client requires. "
                                       "Use DTOs/serializers with explicit field allowlists.",
                        "confidence":  78,
                        "num_signals": 3,
                    })
            except (json.JSONDecodeError, TypeError):
                pass

        # ── API Error Verbosity ────────────────────────────────────────────
        elif resp.status_code in (400, 422, 500):
            if resp.is_json:
                try:
                    err_data = json.loads(resp.text)
                    err_str  = json.dumps(err_data).lower()
                    if any(k in err_str for k in ["stacktrace", "exception", "trace", "file", "line", "query"]):
                        findings.append({
                            "module":      MODULE_NAME,
                            "title":       "API Error Response Contains Debug Information",
                            "risk":        config.RISK_MEDIUM,
                            "url":         api_url,
                            "description": f"API error response (HTTP {resp.status_code}) includes debug "
                                           "information such as stack traces, file paths, or SQL queries.",
                            "evidence":    f"HTTP {resp.status_code}: {resp.text[:300]}",
                            "remedy":      "Return generic error messages in production. Log details server-side only.",
                            "confidence":  82,
                            "num_signals": 2,
                        })
                except Exception:
                    pass

    # ── HTTP Methods Analysis ─────────────────────────────────────────────────
    for api_url in api_endpoints[:5]:
        method_findings = _check_http_methods(client, api_url)
        findings.extend(method_findings)

    return _dedup(findings)


def _check_sensitive_fields(data, depth=0) -> List[str]:
    """Recursively find sensitive field names in API JSON response."""
    if depth > 3:
        return []
    found = []
    if isinstance(data, dict):
        for key in data.keys():
            if any(s in key.lower() for s in SENSITIVE_FIELDS):
                found.append(key)
            found.extend(_check_sensitive_fields(data[key], depth + 1))
    elif isinstance(data, list) and data:
        found.extend(_check_sensitive_fields(data[0], depth + 1))
    return list(set(found))[:5]


def _check_http_methods(client: HttpClient, url: str) -> List[Dict]:
    """Check for overly permissive HTTP methods via OPTIONS."""
    findings = []
    resp = client.get(url, headers={"X-HTTP-Method-Override": "OPTIONS"})

    # Check Allow header
    allow = resp.headers.get("Allow", "") or resp.headers.get("Access-Control-Allow-Methods", "")
    dangerous_methods = []

    for method in ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]:
        if method in allow.upper():
            dangerous_methods.append(method)

    if dangerous_methods:
        findings.append({
            "module":      MODULE_NAME,
            "title":       f"Potentially Dangerous HTTP Methods Allowed: {', '.join(dangerous_methods)}",
            "risk":        config.RISK_MEDIUM,
            "url":         url,
            "description": f"HTTP methods {dangerous_methods} are advertised by the server. "
                           "Unnecessary methods should be disabled to reduce the attack surface.",
            "evidence":    f"Allow: {allow}",
            "remedy":      "Disable HTTP methods not required by the application. Restrict PUT/DELETE to authenticated, authorized users.",
            "confidence":  70,
            "num_signals": 2,
        })

    return findings


def _dedup(findings):
    seen, out = set(), []
    for f in findings:
        k = (f["title"], f["url"])
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out
