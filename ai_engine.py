"""
BugHunter AI v2 - AI Analysis Engine
Combines Claude API reasoning with local heuristic analysis.
Provides contextual vulnerability insights, confidence scoring,
and adaptive mitigation recommendations.
"""

import json
import re
import math
from typing import List, Dict, Optional, Any
from dataclasses import dataclass

import config
from utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class AIInsight:
    summary:        str
    risk_reasoning: str
    confidence_adj: int          # -10 to +10 adjustment to base confidence
    additional_checks: List[str] # suggested follow-up checks
    mitigation:     str


class AIEngine:
    """
    AI analysis engine for contextual vulnerability reasoning.
    Uses Claude API when available, falls back to local heuristics.
    """

    def __init__(self):
        self.api_available = bool(config.ANTHROPIC_API_KEY)
        self._session_findings: List[Dict] = []  # adaptive learning within session
        self._tech_context: Dict = {}

        if self.api_available:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
                log.info("AI Engine: Claude API enabled")
            except ImportError:
                self.api_available = False
                log.warning("AI Engine: anthropic package not installed, using local heuristics")
        else:
            log.info("AI Engine: Running in local heuristic mode (set ANTHROPIC_API_KEY to enable Claude)")

    # ─── Main Analysis Entry ──────────────────────────────────────────────────
    def analyze_findings(
        self,
        findings: List[Dict],
        attack_surface: Dict,
        target: str,
    ) -> Dict:
        """
        Perform deep AI analysis on collected findings.
        Returns enriched findings with reasoning and risk correlations.
        """
        if not findings:
            return {"enriched_findings": [], "correlations": [], "executive_summary": "No issues found."}

        # Update session context (adaptive learning)
        self._session_findings.extend(findings)
        self._tech_context = {
            "technologies": attack_surface.get("technologies", []),
            "total_pages":  len(attack_surface.get("pages", [])),
            "has_api":      len(attack_surface.get("api_endpoints", [])) > 0,
            "has_forms":    len(attack_surface.get("forms", [])) > 0,
        }

        if self.api_available:
            return self._analyze_with_claude(findings, attack_surface, target)
        else:
            return self._analyze_with_heuristics(findings, attack_surface, target)

    # ─── Claude API Analysis ──────────────────────────────────────────────────
    def _analyze_with_claude(
        self,
        findings: List[Dict],
        surface:  Dict,
        target:   str,
    ) -> Dict:
        """Use Claude to perform expert-level analysis."""
        try:
            findings_summary = json.dumps(
                [{
                    "title":       f["title"],
                    "risk":        f["risk"],
                    "module":      f["module"],
                    "description": f["description"],
                    "evidence":    f.get("evidence", "")[:300],
                    "confidence":  f.get("confidence", 50),
                } for f in findings[:20]],  # limit context size
                indent=2
            )

            tech_str = ", ".join(surface.get("technologies", ["Unknown"]))
            surface_summary = (
                f"Pages: {len(surface.get('pages', []))}, "
                f"Forms: {len(surface.get('forms', []))}, "
                f"APIs: {len(surface.get('api_endpoints', []))}, "
                f"Technologies: {tech_str}"
            )

            prompt = f"""You are a senior web application security analyst reviewing findings from an automated scan.

Target: {target}
Attack Surface: {surface_summary}
Scan Findings ({len(findings)} total):
{findings_summary}

Provide:
1. EXECUTIVE SUMMARY (2-3 sentences, business-level risk)
2. TOP 3 CORRELATIONS between findings that together increase risk
3. For each HIGH/CRITICAL finding: one specific, actionable fix
4. RISK PRIORITIZATION: which finding needs immediate attention and why

Respond in JSON with keys: executive_summary, correlations (list), enriched_findings (list with added "ai_reasoning" and "priority_fix"), immediate_action

Be concise, specific, and technical. Reference CVEs where applicable."""

            response = self._client.messages.create(
                model      = config.AI_MODEL,
                max_tokens = config.AI_MAX_TOKENS,
                messages   = [{"role": "user", "content": prompt}],
            )

            raw = response.content[0].text
            # Strip markdown code fences if present
            raw = re.sub(r'^```json\s*|\s*```$', '', raw.strip())

            result = json.loads(raw)

            # Merge AI enrichment back into findings
            enriched = findings.copy()
            ai_map = {f.get("title"): f for f in result.get("enriched_findings", [])}
            for finding in enriched:
                if finding["title"] in ai_map:
                    finding["ai_reasoning"] = ai_map[finding["title"]].get("ai_reasoning", "")
                    finding["priority_fix"] = ai_map[finding["title"]].get("priority_fix", "")

            return {
                "enriched_findings":  enriched,
                "correlations":       result.get("correlations", []),
                "executive_summary":  result.get("executive_summary", ""),
                "immediate_action":   result.get("immediate_action", ""),
                "ai_powered":         True,
            }

        except json.JSONDecodeError:
            log.warning("AI response was not valid JSON, using heuristics")
            return self._analyze_with_heuristics(findings, surface, target)
        except Exception as e:
            log.error(f"Claude API error: {e}")
            return self._analyze_with_heuristics(findings, surface, target)

    # ─── Local Heuristic Analysis ─────────────────────────────────────────────
    def _analyze_with_heuristics(
        self,
        findings: List[Dict],
        surface:  Dict,
        target:   str,
    ) -> Dict:
        """
        Local reasoning engine when API is unavailable.
        Uses correlation rules, severity weighting, and tech-stack awareness.
        """
        enriched   = []
        correlations = []

        # Group findings by category
        by_module: Dict[str, List] = {}
        by_risk:   Dict[str, List] = {}
        for f in findings:
            by_module.setdefault(f.get("module", ""), []).append(f)
            by_risk.setdefault(f.get("risk", "INFO"), []).append(f)

        techs = set(surface.get("technologies", []))

        # ── Correlation Rules ───────────────────────────────────────────────
        # Missing HSTS + Self-signed cert = compounded TLS risk
        hsts_missing = any("HSTS" in f.get("title", "") for f in findings)
        tls_issue    = any("TLS" in f.get("title", "") or "SSL" in f.get("title", "") for f in findings)
        if hsts_missing and tls_issue:
            correlations.append({
                "finding_1": "Missing HSTS",
                "finding_2": "TLS/SSL Weakness",
                "combined_risk": "HIGH",
                "reasoning": "Missing HSTS combined with TLS issues enables full protocol downgrade attacks. "
                             "An attacker can intercept and strip HTTPS, exposing all traffic.",
            })

        # No CSP + Reflected Input = XSS amplified risk
        csp_missing  = any("CSP" in f.get("title", "") or "Content-Security-Policy" in f.get("title", "") for f in findings)
        xss_signal   = any("XSS" in f.get("title", "") or "reflection" in f.get("title", "").lower() for f in findings)
        if csp_missing and xss_signal:
            correlations.append({
                "finding_1": "Missing Content Security Policy",
                "finding_2": "Input Reflection Detected",
                "combined_risk": "CRITICAL",
                "reasoning": "Absence of CSP combined with reflected input creates a high-probability "
                             "XSS attack chain. CSP would have blocked script execution even if injection succeeds.",
            })

        # Info disclosure + Known framework version = targeted exploit risk
        info_disc    = any("disclosure" in f.get("title", "").lower() or "version" in f.get("title", "").lower() for f in findings)
        known_vulns  = techs & {"WordPress", "Drupal", "Joomla"}
        if info_disc and known_vulns:
            correlations.append({
                "finding_1": "Technology/Version Disclosure",
                "finding_2": f"Known CMS: {', '.join(known_vulns)}",
                "combined_risk": "HIGH",
                "reasoning": f"Disclosed version info for {', '.join(known_vulns)} allows attackers to "
                             "cross-reference CVE databases and target specific known vulnerabilities.",
            })

        # Weak cookies + Auth endpoints = session hijack risk
        cookie_weak  = any("cookie" in f.get("title", "").lower() for f in findings)
        auth_present = any("/login" in f.get("url", "") or "/auth" in f.get("url", "") for f in findings)
        if cookie_weak and auth_present:
            correlations.append({
                "finding_1": "Insecure Cookie Configuration",
                "finding_2": "Authentication Endpoints Detected",
                "combined_risk": "HIGH",
                "reasoning": "Insecure session cookies on authenticated endpoints enable session hijacking "
                             "via network interception or XSS-based theft.",
            })

        # ── Enrich individual findings ───────────────────────────────────────
        for finding in findings:
            enriched_finding = dict(finding)
            enriched_finding["ai_reasoning"]  = self._generate_reasoning(finding, techs)
            enriched_finding["priority_fix"]  = self._generate_fix(finding)
            enriched_finding["confidence"]    = self._adjust_confidence(finding, techs, by_risk)
            enriched.append(enriched_finding)

        # ── Executive Summary ────────────────────────────────────────────────
        crit_count = len(by_risk.get(config.RISK_CRITICAL, []))
        high_count = len(by_risk.get(config.RISK_HIGH, []))
        med_count  = len(by_risk.get(config.RISK_MEDIUM, []))
        total      = len(findings)

        if crit_count > 0:
            risk_level = "CRITICAL risk posture"
        elif high_count > 0:
            risk_level = "HIGH risk posture"
        elif med_count > 0:
            risk_level = "MODERATE risk posture"
        else:
            risk_level = "LOW risk posture"

        exec_summary = (
            f"Security analysis of {target} identified {total} findings representing a {risk_level}. "
            f"Stack includes: {', '.join(list(techs)[:4]) or 'undetected technologies'}. "
        )
        if crit_count:
            exec_summary += f"Immediate attention required for {crit_count} critical issue(s). "
        if correlations:
            exec_summary += f"{len(correlations)} compound risk correlation(s) detected that amplify individual findings."

        return {
            "enriched_findings": enriched,
            "correlations":      correlations,
            "executive_summary": exec_summary,
            "immediate_action":  self._get_immediate_action(by_risk),
            "ai_powered":        False,
        }

    # ─── Reasoning Generator ─────────────────────────────────────────────────
    def _generate_reasoning(self, finding: Dict, techs: set) -> str:
        title  = finding.get("title", "").lower()
        risk   = finding.get("risk", "")
        module = finding.get("module", "")

        reasons = {
            "xss":        "Reflected/stored script injection can lead to session theft, credential harvesting, "
                          "and UI redressing attacks. Modern browsers provide partial mitigation, but no complete protection.",
            "sqli":       "SQL injection allows data exfiltration, authentication bypass, and in some configurations, "
                          "remote code execution. Impact is severe when combined with elevated database privileges.",
            "csrf":       "Cross-site request forgery enables unauthorized actions performed on behalf of authenticated users. "
                          "Severity increases when targeting state-changing operations like password changes or transfers.",
            "cors":       "Misconfigured CORS allows malicious origins to make credentialed cross-origin requests, "
                          "potentially accessing authenticated API endpoints and sensitive data.",
            "hsts":       "Without HSTS, connections can be downgraded to HTTP by active network attackers, "
                          "exposing session tokens and sensitive data in transit.",
            "csp":        "Content Security Policy is the primary browser-enforced defense against XSS. "
                          "Its absence means any successful script injection executes without restriction.",
            "cookie":     "Insecure cookie attributes allow theft via network sniffing (no Secure), "
                          "JavaScript access (no HttpOnly), or cross-site embedding (no SameSite).",
            "disclosure": "Technology and version disclosure helps attackers map the exact CVE landscape, "
                          "enabling targeted attacks on known vulnerabilities.",
            "redirect":   "Open redirects are leveraged in phishing campaigns to create trusted-looking URLs "
                          "that redirect to attacker-controlled domains.",
            "traversal":  "Path traversal enables access to files outside the web root, potentially exposing "
                          "configuration files, credentials, and source code.",
            "timing":     "Timing differences in authentication responses can confirm valid usernames, "
                          "enabling targeted brute-force attacks.",
        }

        for key, reason in reasons.items():
            if key in title or key in module.lower():
                return reason

        return (
            f"This finding in module '{module}' indicates a security control gap. "
            f"At {risk} severity, this warrants investigation and remediation based on your risk tolerance."
        )

    def _generate_fix(self, finding: Dict) -> str:
        title  = finding.get("title", "").lower()
        module = finding.get("module", "")

        fixes = {
            "hsts":        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "csp":         "Implement a restrictive CSP: Content-Security-Policy: default-src 'self'; script-src 'self'",
            "x-frame":     "Add: X-Frame-Options: DENY or SAMEORIGIN",
            "x-content":   "Add: X-Content-Type-Options: nosniff",
            "cookie":      "Set all session cookies with: Secure; HttpOnly; SameSite=Strict",
            "cors":         "Restrict CORS to explicit trusted origins. Never reflect Origin header without validation.",
            "csrf":        "Implement double-submit cookie pattern or synchronizer token. Use SameSite=Strict cookies.",
            "disclosure":  "Remove or mask X-Powered-By and Server headers in server configuration.",
            "redirect":    "Validate redirect destinations against an allowlist. Never accept user-controlled redirect URLs.",
            "traversal":   "Use realpath() normalization and validate paths are within the expected root directory.",
            "xss":         "Encode all output context-appropriately. Implement a strict CSP. Validate/sanitize inputs.",
            "sqli":        "Use parameterized queries exclusively. Apply least-privilege database accounts.",
            "graphql":     "Disable introspection in production. Implement depth limiting and query cost analysis.",
        }

        for key, fix in fixes.items():
            if key in title or key in module.lower():
                return fix

        return f"Review '{finding.get('title', '')}' against OWASP guidelines and apply defense-in-depth controls."

    def _adjust_confidence(self, finding: Dict, techs: set, by_risk: Dict) -> int:
        base = finding.get("confidence", 50)
        adj  = 0

        # Boost confidence if technology matches finding context
        tech_boosts = {
            "wordpress":  {"WordPress"},
            "drupal":     {"Drupal"},
            "graphql":    {"GraphQL"},
            "angular":    {"Angular"},
        }
        title = finding.get("title", "").lower()
        for key, tech_set in tech_boosts.items():
            if key in title and techs & tech_set:
                adj += 10
                break

        # Multiple same-risk findings slightly lower individual confidence (dilution)
        same_risk_count = len(by_risk.get(finding.get("risk", ""), []))
        if same_risk_count > 5:
            adj -= 5

        return max(5, min(99, base + adj))

    def _get_immediate_action(self, by_risk: Dict) -> str:
        crits = by_risk.get(config.RISK_CRITICAL, [])
        highs = by_risk.get(config.RISK_HIGH, [])

        if crits:
            return f"IMMEDIATE: Address '{crits[0].get('title', 'critical finding')}' — this poses the highest exploitation risk."
        elif highs:
            return f"PRIORITY: Address '{highs[0].get('title', 'high severity finding')}' within 24–48 hours."
        return "No immediate critical action required. Address medium findings in the next sprint."

    # ─── Entropy Analysis ─────────────────────────────────────────────────────
    @staticmethod
    def calculate_entropy(data: str) -> float:
        """Shannon entropy of a string — used to detect potential secrets/tokens."""
        if not data:
            return 0.0
        freq = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        length = len(data)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    @staticmethod
    def is_high_entropy(token: str, threshold: float = 4.0) -> bool:
        """Return True if a token has high entropy (likely a secret/key)."""
        return (
            len(token) >= 16
            and AIEngine.calculate_entropy(token) >= threshold
        )

    # ─── Response Diff Analysis ───────────────────────────────────────────────
    @staticmethod
    def diff_responses(r1_text: str, r2_text: str) -> Dict:
        """
        Compare two responses for meaningful differences.
        Used in blind detection scenarios.
        """
        len_diff = abs(len(r1_text) - len(r2_text))
        len_ratio = len_diff / max(len(r1_text), len(r2_text), 1)

        # Token-level diff (simplified)
        words1 = set(r1_text.split())
        words2 = set(r2_text.split())
        unique_to_r2 = words2 - words1

        error_words = {"error", "exception", "warning", "syntax", "undefined", "null", "fatal"}
        new_errors = [w for w in unique_to_r2 if w.lower() in error_words]

        return {
            "length_diff_bytes": len_diff,
            "length_diff_ratio": round(len_ratio, 3),
            "significant":       len_ratio > 0.10,
            "new_error_tokens":  new_errors,
            "new_content_count": len(unique_to_r2),
        }
