"""
BugHunter AI v2 - SQL Injection Detection Module (SAFE)
Detects SQLi indicators via error messages and timing anomalies.
Uses safe probes — NO data extraction, NO blind UNION, NO destructive queries.
"""

import re
import time
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs

from core.http_client import HttpClient
from core.ai_engine import AIEngine
import config

MODULE_NAME = "SQLiDetector"

# Safe probes — these trigger error disclosure without extracting data
SAFE_PROBES = [
    ("'",        "Single quote — tests for unescaped string termination"),
    ("\"",       "Double quote — tests for double-quoted string context"),
    ("`",        "Backtick — MySQL identifier quoting"),
    ("1 AND 1=1","Boolean true — tests for numeric context"),
    ("1 AND 1=2","Boolean false — detects differential responses"),
]

# SQL error fingerprints (detection-only, not extraction)
SQL_ERROR_PATTERNS = {
    "MySQL":      [
        r"you have an error in your sql syntax",
        r"mysql_fetch", r"mysql_num_rows", r"mysql_query",
        r"com\.mysql\.jdbc", r"supplied argument is not a valid mysql",
        r"warning.*mysqli", r"unclosed quotation mark",
    ],
    "PostgreSQL": [
        r"pg_query\(\)", r"pg_exec\(\)", r"unterminated quoted string",
        r"pg::syntaxerror", r"postgresql.*error", r"invalid input syntax for",
    ],
    "MSSQL":      [
        r"unclosed quotation mark after the character string",
        r"quoted_identifier", r"microsoft ole db provider for sql server",
        r"incorrect syntax near", r"mssql_query\(\)",
        r"supplied argument is not a valid ms sql server",
    ],
    "Oracle":     [
        r"ora-\d{4,5}", r"oracle error", r"quoted string not properly terminated",
        r"invalid relational operator",
    ],
    "SQLite":     [
        r"sqlite3::query", r"sqlite_query", r"sqlite error",
        r"unrecognized token:", r"no such column:",
    ],
    "Generic":    [
        r"sql syntax", r"sql error", r"database error",
        r"syntax error.*query", r"database query failed",
        r"error in your sql", r"invalid query",
    ],
}


def analyze(client: HttpClient, url: str, surface: Dict, mode: str = config.MODE_PASSIVE, **kwargs) -> List[Dict]:
    findings = []

    # ── PASSIVE: Error Pattern in Existing Responses ──────────────────────────
    for page_url in list(surface.get("pages", []))[:30]:
        resp = client.get(page_url)
        if not resp.ok:
            continue
        db_type, evidence = _check_sql_errors(resp.text)
        if db_type:
            findings.append({
                "module":      MODULE_NAME,
                "title":       f"SQL Error Message Disclosed ({db_type})",
                "risk":        config.RISK_HIGH,
                "url":         page_url,
                "description": f"The page returns a {db_type} SQL error message in the response. "
                               "This discloses database type, query structure, and internal paths, "
                               "directly aiding SQL injection attacks.",
                "evidence":    evidence[:300],
                "remedy":      "Implement generic error pages. Log errors server-side only. "
                               "Use parameterized queries to prevent SQL injection.",
                "confidence":  90,
                "num_signals": 3,
            })

    # ── ACTIVE (Safe): Probe URL Parameters for SQLi Indicators ──────────────
    if mode == config.MODE_ACTIVE:
        tested = set()

        for page_url in list(surface.get("pages", []))[:20]:
            parsed = urlparse(page_url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            for param in list(params.keys())[:3]:
                key = (page_url.split("?")[0], param)
                if key in tested:
                    continue
                tested.add(key)

                # Get baseline response
                baseline = client.get(page_url)
                if not baseline.ok:
                    continue

                # Error-based detection (safe single quote probe)
                quote_findings = _test_error_based(client, page_url, param, params, baseline.text)
                findings.extend(quote_findings)

                # Timing anomaly detection (safe — checks timing difference only)
                timing_findings = _test_timing_anomaly(client, page_url, param, params)
                findings.extend(timing_findings)

        # Form-based parameter testing
        for form in surface.get("forms", [])[:10]:
            form_findings = _test_form_sqli(client, form)
            findings.extend(form_findings)

    return _deduplicate(findings)


# ─── Error-Based Detection ────────────────────────────────────────────────────
def _test_error_based(
    client: HttpClient, url: str, param: str,
    params: Dict, baseline_text: str
) -> List[Dict]:
    findings = []
    base_url = url.split("?")[0]

    for probe_value, probe_desc in SAFE_PROBES[:2]:  # Only single/double quote
        test_params = {k: v[0] for k, v in params.items()}
        test_params[param] = probe_value

        resp = client.get(base_url, params=test_params)
        if not resp.ok:
            continue

        db_type, evidence = _check_sql_errors(resp.text)
        if db_type:
            diff = AIEngine.diff_responses(baseline_text, resp.text)
            findings.append({
                "module":      MODULE_NAME,
                "title":       f"SQL Injection Error Triggered: {param} ({db_type})",
                "risk":        config.RISK_CRITICAL,
                "url":         url,
                "description": f"Injecting a {probe_desc} into parameter '{param}' triggered a "
                               f"{db_type} SQL error response. This confirms the parameter is "
                               "inserted directly into a SQL query without proper sanitization.",
                "evidence":    f"Probe: '{probe_value}' in {param}\nError: {evidence[:250]}",
                "remedy":      "Immediately replace string concatenation with parameterized queries. "
                               "Apply input validation and least-privilege database accounts.",
                "confidence":  92,
                "num_signals": 4,
            })
            break  # One finding per parameter is enough

    return findings


# ─── Timing-Based Detection ───────────────────────────────────────────────────
def _test_timing_anomaly(
    client: HttpClient, url: str, param: str, params: Dict
) -> List[Dict]:
    """
    Detect time-based SQL injection by measuring response time differences.
    Uses a simple delay-triggering approach (non-destructive integer probe).
    This does NOT use SLEEP() or WAITFOR — just measures natural timing variance.
    """
    findings = []
    base_url = url.split("?")[0]

    # Baseline timing (3 samples)
    base_params = {k: v[0] for k, v in params.items()}
    baseline_time = client.get_with_timing(base_url, params=base_params, n=3)

    if baseline_time <= 0:
        return findings

    # NOTE: We specifically do NOT include SLEEP/WAITFOR payloads.
    # We only measure if an unexpected large timing difference occurs naturally
    # when injecting a safe numeric comparison that changes query logic.
    test_params = dict(base_params)
    test_params[param] = "1 AND 1=1"  # Semantically equivalent — tests numeric context

    probe_time = client.get_with_timing(base_url, params=test_params, n=2)

    # If timing difference is extremely large (> 5x), something unusual is happening
    if probe_time > 0 and baseline_time > 0:
        ratio = probe_time / baseline_time
        if ratio > 5.0 and probe_time > 3000:  # >5x slower AND >3s absolute
            findings.append({
                "module":      MODULE_NAME,
                "title":       f"Significant Timing Anomaly on Parameter: {param}",
                "risk":        config.RISK_MEDIUM,
                "url":         url,
                "description": f"Parameter '{param}' shows a {ratio:.1f}x timing difference when "
                               "a boolean probe is injected. This may indicate conditional query execution "
                               "and warrants manual investigation for time-based blind SQLi.",
                "evidence":    f"Baseline: {baseline_time:.0f}ms, Probe: {probe_time:.0f}ms, "
                               f"Ratio: {ratio:.1f}x",
                "remedy":      "Investigate with a security professional. Implement parameterized queries.",
                "confidence":  55,  # Lower confidence — timing varies
                "num_signals": 2,
            })

    return findings


# ─── Form-Based SQLi Detection ────────────────────────────────────────────────
def _test_form_sqli(client: HttpClient, form: Dict) -> List[Dict]:
    findings = []
    action  = form.get("action", "")
    method  = form.get("method", "GET")
    inputs  = form.get("inputs", [])

    if not action:
        return findings

    # Build baseline data
    base_data = {}
    text_fields = []
    for inp in inputs:
        if inp.get("type") in ("text", "search", "email", ""):
            base_data[inp["name"]] = "test"
            text_fields.append(inp["name"])
        else:
            base_data[inp["name"]] = inp.get("value", "1")

    if not text_fields:
        return findings

    # Get baseline
    if method == "POST":
        baseline = client.post(action, data=base_data)
    else:
        baseline = client.get(action, params=base_data)

    if not baseline.ok:
        return findings

    # Probe with single quote in first text field
    test_data = dict(base_data)
    test_data[text_fields[0]] = "'"

    if method == "POST":
        probe_resp = client.post(action, data=test_data)
    else:
        probe_resp = client.get(action, params=test_data)

    if not probe_resp.ok:
        return findings

    db_type, evidence = _check_sql_errors(probe_resp.text)
    if db_type and db_type not in baseline.text:
        findings.append({
            "module":      MODULE_NAME,
            "title":       f"Form SQLi Error Triggered: {text_fields[0]} ({db_type})",
            "risk":        config.RISK_CRITICAL,
            "url":         action,
            "description": f"Injecting a single quote into form field '{text_fields[0]}' on "
                           f"'{action}' triggered a {db_type} SQL error.",
            "evidence":    f"Field: {text_fields[0]}, Form action: {action}\nError: {evidence[:250]}",
            "remedy":      "Immediately implement parameterized queries for all form-handling code.",
            "confidence":  91,
            "num_signals": 4,
        })

    return findings


# ─── SQL Error Checker ────────────────────────────────────────────────────────
def _check_sql_errors(html: str) -> tuple:
    """Returns (db_type, evidence_snippet) or (None, None)."""
    html_lower = html.lower()
    for db_type, patterns in SQL_ERROR_PATTERNS.items():
        for pattern in patterns:
            m = re.search(pattern, html_lower)
            if m:
                start = max(0, m.start() - 50)
                end   = min(len(html), m.end() + 150)
                return db_type, html[start:end].strip()
    return None, None


def _deduplicate(findings: List[Dict]) -> List[Dict]:
    seen = set()
    unique = []
    for f in findings:
        key = f["title"] + f["url"]
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
