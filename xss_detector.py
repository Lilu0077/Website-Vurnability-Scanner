"""
BugHunter AI v2 - XSS Detection Module (SAFE - Detection Only)
Detects reflection and DOM-based XSS vectors using safe canary tokens.
NO harmful payloads. NO exploitation.
"""

import re
import html as html_lib
from typing import List, Dict
from urllib.parse import urlencode, urlparse, parse_qs
from core.http_client import HttpClient
from core.ai_engine import AIEngine
import config

MODULE_NAME = "XSSDetector"

# Safe canary that has no side effects but tests reflection
SAFE_CANARY = f"bh{config.SAFE_CANARY_STRING}7a"

# DOM sink patterns in JavaScript (passive)
DOM_SINK_PATTERNS = [
    (r'document\.write\s*\(',          "document.write() sink"),
    (r'innerHTML\s*=',                  "innerHTML assignment"),
    (r'outerHTML\s*=',                  "outerHTML assignment"),
    (r'insertAdjacentHTML\s*\(',        "insertAdjacentHTML sink"),
    (r'eval\s*\(',                      "eval() call"),
    (r'setTimeout\s*\([\'"]',           "setTimeout with string"),
    (r'setInterval\s*\([\'"]',          "setInterval with string"),
    (r'location\.href\s*=',             "location.href assignment"),
    (r'location\.replace\s*\(',         "location.replace sink"),
    (r'window\.location\s*=',           "window.location assignment"),
    (r'\.src\s*=.*(?:location|param)',  "Dynamic src from URL params"),
]

# Source patterns that pull from URL/user-controlled data
DOM_SOURCE_PATTERNS = [
    r'location\.(?:search|hash|href)',
    r'document\.(?:URL|referrer)',
    r'window\.name',
    r'URLSearchParams',
]


def analyze(client: HttpClient, url: str, surface: Dict, mode: str = config.MODE_PASSIVE, **kwargs) -> List[Dict]:
    findings = []

    # ── PASSIVE: DOM Sink Analysis ────────────────────────────────────────────
    # Inspect JS files for dangerous sinks fed by URL-controlled sources
    for js_url in list(surface.get("js_files", []))[:20]:
        resp = client.get(js_url)
        if not resp.ok:
            continue
        js_findings = _analyze_dom_sinks(resp.text, js_url)
        findings.extend(js_findings)

    # Inline scripts on main pages
    from bs4 import BeautifulSoup
    for page_url in list(surface.get("pages", []))[:15]:
        resp = client.get(page_url)
        if not resp.ok or not resp.is_html:
            continue
        try:
            soup = BeautifulSoup(resp.text, "lxml")
        except Exception:
            soup = BeautifulSoup(resp.text, "html.parser")

        for script in soup.find_all("script"):
            if script.string:
                js_findings = _analyze_dom_sinks(script.string, page_url)
                findings.extend(js_findings)

    # ── ACTIVE (Safe): Canary Reflection Testing ──────────────────────────────
    if mode == config.MODE_ACTIVE:
        # Test reflected parameters using safe canary string
        params = list(surface.get("parameters", set()))
        for page_url in list(surface.get("pages", []))[:20]:
            parsed = urlparse(page_url)
            page_params = list(parse_qs(parsed.query).keys())
            if not page_params:
                continue

            for param in page_params[:3]:  # limit probes per page
                reflected = _test_reflection(client, page_url, param)
                if reflected:
                    # Check if the canary is reflected in a JS/HTML context
                    context = _determine_reflection_context(reflected["response_text"], SAFE_CANARY)
                    risk    = config.RISK_HIGH if context in ("script", "attribute", "href") else config.RISK_MEDIUM
                    findings.append({
                        "module":      MODULE_NAME,
                        "title":       f"Input Reflection Detected: {param} (context: {context})",
                        "risk":        risk,
                        "url":         page_url,
                        "description": f"The parameter '{param}' reflects user input in the response "
                                       f"within a '{context}' context. This is a strong XSS indicator "
                                       "requiring manual verification with encoded payloads.",
                        "evidence":    f"Canary '{SAFE_CANARY}' reflected in {context} context. "
                                       f"Response excerpt: ...{reflected['snippet']}...",
                        "remedy":      "Encode all reflected output using context-appropriate escaping "
                                       "(HTML encode for HTML, JS encode for JS, etc.). "
                                       "Implement a strict CSP as a second layer of defense.",
                        "confidence":  80 if context in ("script", "attribute") else 65,
                        "num_signals": 3 if context == "script" else 2,
                    })

        # Forms: test reflection via form submission
        for form in surface.get("forms", [])[:10]:
            form_findings = _test_form_reflection(client, form)
            findings.extend(form_findings)

    return _deduplicate(findings)


# ─── DOM Sink Analysis ────────────────────────────────────────────────────────
def _analyze_dom_sinks(js_content: str, source_url: str) -> List[Dict]:
    findings = []
    has_source = any(re.search(p, js_content) for p in DOM_SOURCE_PATTERNS)

    if not has_source:
        return findings  # No URL-controlled data source → skip

    for pattern, sink_name in DOM_SINK_PATTERNS:
        matches = list(re.finditer(pattern, js_content, re.I))
        if not matches:
            continue

        # Get code context around match
        m = matches[0]
        start = max(0, m.start() - 100)
        end   = min(len(js_content), m.end() + 100)
        snippet = js_content[start:end].strip()

        # Determine if sink is plausibly connected to a source (proximity heuristic)
        surrounding = js_content[max(0, m.start()-300):m.end()+300]
        source_nearby = any(re.search(p, surrounding) for p in DOM_SOURCE_PATTERNS)

        if source_nearby:
            findings.append({
                "module":      MODULE_NAME,
                "title":       f"Potential DOM XSS: {sink_name} Fed by URL Source",
                "risk":        config.RISK_HIGH,
                "url":         source_url,
                "description": f"JavaScript code uses '{sink_name}' with data that appears to originate "
                               "from a URL-controlled source (location.search, location.hash, etc.). "
                               "This pattern is characteristic of DOM-based XSS.",
                "evidence":    f"Sink: {sink_name}\nContext: ...{snippet[:200]}...",
                "remedy":      "Never pass URL-derived data to HTML sinks without proper sanitization. "
                               "Use textContent instead of innerHTML. Sanitize with DOMPurify if HTML is required.",
                "confidence":  72,
                "num_signals": 3,
            })
            break  # One finding per JS file for this pattern

    return findings


# ─── Reflection Testing (Safe) ────────────────────────────────────────────────
def _test_reflection(client: HttpClient, url: str, param: str) -> Dict | None:
    """Send a safe canary and check if it's reflected in the response."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param] = [SAFE_CANARY]

    test_url = url.split("?")[0]
    resp = client.get(test_url, params={k: v[0] for k, v in params.items()})

    if not resp.ok:
        return None

    if SAFE_CANARY in resp.text:
        # Find snippet
        idx = resp.text.find(SAFE_CANARY)
        start = max(0, idx - 30)
        end   = min(len(resp.text), idx + len(SAFE_CANARY) + 30)
        return {
            "response_text": resp.text,
            "snippet":       resp.text[start:end],
        }
    return None


def _test_form_reflection(client: HttpClient, form: Dict) -> List[Dict]:
    """Test form inputs for reflection using a safe canary."""
    findings = []
    action  = form.get("action", "")
    method  = form.get("method", "GET")
    inputs  = form.get("inputs", [])

    if not action or not inputs:
        return findings

    # Only test text-type inputs
    test_data = {}
    probed_fields = []
    for inp in inputs[:5]:
        if inp.get("type") in ("text", "search", "email", "url", ""):
            test_data[inp["name"]] = SAFE_CANARY
            probed_fields.append(inp["name"])
        elif inp.get("type") in ("hidden",):
            test_data[inp["name"]] = inp.get("value", "")
        else:
            test_data[inp["name"]] = inp.get("value", "test")

    if not probed_fields:
        return findings

    if method == "POST":
        resp = client.post(action, data=test_data)
    else:
        resp = client.get(action, params=test_data)

    if resp.ok and SAFE_CANARY in resp.text:
        idx = resp.text.find(SAFE_CANARY)
        start = max(0, idx - 30)
        end   = min(len(resp.text), idx + len(SAFE_CANARY) + 30)
        snippet = resp.text[start:end]
        context = _determine_reflection_context(resp.text, SAFE_CANARY)

        findings.append({
            "module":      MODULE_NAME,
            "title":       f"Form Input Reflection: Fields {probed_fields} → Response",
            "risk":        config.RISK_HIGH if context in ("script", "attribute") else config.RISK_MEDIUM,
            "url":         action,
            "description": f"Form submission with canary value in fields {probed_fields} produced "
                           f"reflection in the response within '{context}' context.",
            "evidence":    f"Form: {action}, Method: {method}, Reflected in: {context}\nSnippet: {snippet[:150]}",
            "remedy":      "Output-encode all reflected form data. Validate input server-side. Implement CSP.",
            "confidence":  78,
            "num_signals": 2,
        })

    return findings


def _determine_reflection_context(html: str, canary: str) -> str:
    """Determine the HTML/JS context where a canary is reflected."""
    idx = html.find(canary)
    if idx == -1:
        return "unknown"

    preceding = html[max(0, idx - 500):idx].lower()

    # Script context
    script_opens  = preceding.count("<script")
    script_closes = preceding.count("</script")
    if script_opens > script_closes:
        return "script"

    # Attribute context
    if re.search(r'<[a-z]+[^>]*\s[a-z-]+=\s*[\'"][^>]*$', html[max(0, idx-200):idx], re.I):
        # Check if in href/src specifically
        attr_ctx = re.search(r'\s(href|src|action|data-[^=]*)=[\'"]?[^>]*$',
                              html[max(0, idx-200):idx], re.I)
        if attr_ctx:
            return f"attribute:{attr_ctx.group(1)}"
        return "attribute"

    # Comment context
    comment_opens  = preceding.count("<!--")
    comment_closes = preceding.count("-->")
    if comment_opens > comment_closes:
        return "comment"

    return "html_body"


def _deduplicate(findings: List[Dict]) -> List[Dict]:
    seen = set()
    unique = []
    for f in findings:
        key = (f["title"], f["url"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
