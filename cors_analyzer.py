"""
BugHunter AI v2 - CORS Analyzer Module
"""
import re
from typing import List, Dict
from core.http_client import HttpClient
import config

MODULE_NAME = "CORSAnalyzer"

CORS_TEST_ORIGINS = [
    "https://evil.com",
    "null",
    "https://target.attacker.com",
]


def analyze(client: HttpClient, url: str, surface: Dict, **kwargs) -> List[Dict]:
    findings = []

    test_urls = [url] + list(surface.get("api_endpoints", []))[:10]

    for test_url in test_urls:
        for origin in CORS_TEST_ORIGINS:
            resp = client.get(test_url, headers={"Origin": origin})
            if not resp.ok:
                continue

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            if not acao:
                continue

            # Wildcard
            if acao == "*":
                findings.append(_finding(
                    title       = "CORS Wildcard Origin Configured",
                    risk        = config.RISK_MEDIUM,
                    url         = test_url,
                    description = "The endpoint returns Access-Control-Allow-Origin: * allowing any site "
                                  "to make cross-origin requests. Sensitive APIs should restrict origins.",
                    evidence    = f"Origin sent: {origin}\nAccess-Control-Allow-Origin: {acao}",
                    remedy      = "Restrict CORS to an explicit origin allowlist.",
                    confidence  = 88,
                ))

            # Origin reflection without validation
            elif acao == origin and origin not in ("null", "*"):
                if acac == "true":
                    findings.append(_finding(
                        title       = "CORS Origin Reflection with Credentials Enabled (Critical)",
                        risk        = config.RISK_CRITICAL,
                        url         = test_url,
                        description = f"The server reflects the attacker-controlled Origin '{origin}' and "
                                      "sets Access-Control-Allow-Credentials: true. This allows any malicious "
                                      "website to make authenticated cross-origin requests, leaking user data.",
                        evidence    = f"Origin: {origin} → ACAO: {acao}, ACAC: true",
                        remedy      = "Validate Origin against a strict allowlist before reflecting. "
                                      "Never reflect arbitrary origins when credentials=true.",
                        confidence  = 93,
                    ))
                else:
                    findings.append(_finding(
                        title       = "CORS Origin Reflected Without Validation",
                        risk        = config.RISK_HIGH,
                        url         = test_url,
                        description = f"The server reflects the request Origin header without apparent validation.",
                        evidence    = f"Origin: {origin} → ACAO: {acao}",
                        remedy      = "Maintain an explicit allowlist of trusted origins. Never use regex with broad patterns.",
                        confidence  = 80,
                    ))

            # null origin
            if acao == "null":
                findings.append(_finding(
                    title       = "CORS Allows null Origin",
                    risk        = config.RISK_HIGH,
                    url         = test_url,
                    description = "Server accepts the 'null' origin, which can be triggered from sandboxed "
                                  "iframes and local HTML files — a known CORS bypass technique.",
                    evidence    = f"Access-Control-Allow-Origin: null",
                    remedy      = "Remove 'null' from allowed origins. It should never be trusted.",
                    confidence  = 90,
                ))
            break  # one origin test per URL is enough for initial scan

    return _dedup(findings)


def _finding(title, risk, url, description, evidence, remedy, confidence=80) -> Dict:
    return {"module": MODULE_NAME, "title": title, "risk": risk, "url": url,
            "description": description, "evidence": evidence, "remedy": remedy,
            "confidence": confidence, "num_signals": 2}


def _dedup(findings):
    seen, out = set(), []
    for f in findings:
        k = (f["title"], f["url"])
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out
