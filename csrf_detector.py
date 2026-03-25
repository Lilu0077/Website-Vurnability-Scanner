"""
BugHunter AI v2 - CSRF Detector
"""
import re
from typing import List, Dict
from core.http_client import HttpClient
import config

MODULE_NAME_CSRF = "CSRFDetector"


def analyze_csrf(client: HttpClient, url: str, surface: Dict, **kwargs) -> List[Dict]:
    findings = []

    for form in surface.get("forms", []):
        action = form.get("action", url)
        method = form.get("method", "GET")
        inputs = form.get("inputs", [])
        has_csrf_token = form.get("csrf_token", False)

        if method != "POST":
            continue

        # Check for state-changing POST forms without CSRF protection
        is_state_changing = any(
            re.search(r'(password|email|account|settings|profile|transfer|payment|delete|admin|user)',
                      (inp.get("name", "") + action), re.I)
            for inp in inputs
        ) or any(
            re.search(r'(update|save|change|create|delete|modify)', action, re.I)
        )

        if not has_csrf_token and is_state_changing:
            # Check if SameSite cookie protection is in place
            has_samesite = any(
                c.get("samesite", "").lower() in ("strict", "lax")
                for c in surface.get("cookies", {}).values()
            )

            risk = config.RISK_HIGH if not has_samesite else config.RISK_MEDIUM
            findings.append({
                "module":      MODULE_NAME_CSRF,
                "title":       f"CSRF Token Missing on State-Changing Form: {action}",
                "risk":        risk,
                "url":         action,
                "description": f"POST form to '{action}' appears to perform state-changing operations "
                               "but contains no CSRF token. Without SameSite=Strict cookies or CSRF tokens, "
                               "cross-origin requests can forge actions on behalf of authenticated users.",
                "evidence":    f"Form action: {action}, Method: POST, CSRF token: absent, "
                               f"SameSite protection: {'yes' if has_samesite else 'no'}",
                "remedy":      "Implement the Synchronizer Token Pattern: generate unique per-session tokens "
                               "for all state-changing forms. Alternatively, set SameSite=Strict on session cookies.",
                "confidence":  78,
                "num_signals": 2,
            })

    return findings
