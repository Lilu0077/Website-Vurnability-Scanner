"""
BugHunter AI v2 - Dynamic Risk Scoring Engine
Assigns confidence-weighted risk scores to findings.
"""

from typing import Dict, List, Optional
import config


class RiskScorer:
    """
    Computes dynamic risk scores for security findings.
    Takes into account: severity, confidence, number of signals,
    endpoint sensitivity, and technology context.
    """

    # Base scores per risk level
    BASE_SCORES = {
        config.RISK_CRITICAL: 90,
        config.RISK_HIGH:     70,
        config.RISK_MEDIUM:   45,
        config.RISK_LOW:      20,
        config.RISK_INFO:     5,
    }

    # Sensitive endpoint path multipliers
    SENSITIVE_PATHS = {
        r'/admin':    1.3,
        r'/login':    1.2,
        r'/api':      1.2,
        r'/payment':  1.4,
        r'/auth':     1.2,
        r'/upload':   1.3,
        r'/password': 1.3,
        r'/token':    1.3,
        r'/graphql':  1.2,
    }

    def score_finding(
        self,
        risk_level:   str,
        confidence:   int,
        num_signals:  int         = 1,
        url:          str         = "",
        evidence_rich: bool       = False,
    ) -> Dict:
        """
        Compute a composite risk score.
        Returns a dict with numeric_score (0–100) and risk_label.
        """
        base = self.BASE_SCORES.get(risk_level, 5)

        # Confidence factor (0.5 to 1.0 range)
        conf_factor = 0.5 + (confidence / 200)

        # Multi-signal boost (more indicators = higher confidence)
        signal_boost = min(1.0 + (num_signals - 1) * 0.05, 1.25)

        # Endpoint sensitivity multiplier
        path_mult = 1.0
        import re
        for pattern, mult in self.SENSITIVE_PATHS.items():
            if re.search(pattern, url, re.I):
                path_mult = max(path_mult, mult)
                break

        # Evidence richness bonus
        evidence_bonus = 5 if evidence_rich else 0

        raw_score = (base * conf_factor * signal_boost * path_mult) + evidence_bonus
        final     = max(1, min(100, round(raw_score)))

        return {
            "numeric_score": final,
            "risk_label":    self._label_from_score(final),
            "factors": {
                "base_score":       base,
                "confidence":       confidence,
                "signal_count":     num_signals,
                "path_multiplier":  path_mult,
            }
        }

    def _label_from_score(self, score: int) -> str:
        if score >= 80: return config.RISK_CRITICAL
        if score >= 60: return config.RISK_HIGH
        if score >= 35: return config.RISK_MEDIUM
        if score >= 15: return config.RISK_LOW
        return config.RISK_INFO

    def prioritize_findings(self, findings: List[Dict]) -> List[Dict]:
        """Sort findings by composite risk score descending."""
        order = {
            config.RISK_CRITICAL: 4,
            config.RISK_HIGH:     3,
            config.RISK_MEDIUM:   2,
            config.RISK_LOW:      1,
            config.RISK_INFO:     0,
        }
        return sorted(
            findings,
            key=lambda f: (order.get(f.get("risk", config.RISK_INFO), 0),
                           f.get("confidence", 0)),
            reverse=True,
        )

    def compute_overall_risk(self, findings: List[Dict]) -> str:
        """Compute the overall risk level from all findings."""
        if not findings:
            return config.RISK_INFO
        risk_order = [config.RISK_CRITICAL, config.RISK_HIGH, config.RISK_MEDIUM,
                      config.RISK_LOW, config.RISK_INFO]
        risk_set = {f.get("risk", config.RISK_INFO) for f in findings}
        for level in risk_order:
            if level in risk_set:
                return level
        return config.RISK_INFO
