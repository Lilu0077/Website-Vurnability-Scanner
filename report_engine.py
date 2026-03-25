"""
BugHunter AI v2 - Reporting Engine
Generates JSON, HTML dashboard, and Markdown reports from scan results.
"""

import json
import os
from datetime import datetime
from typing import Dict, List
from pathlib import Path

import config

RISK_COLORS_HEX = {
    config.RISK_CRITICAL: "#ff4444",
    config.RISK_HIGH:     "#ff8800",
    config.RISK_MEDIUM:   "#ffcc00",
    config.RISK_LOW:      "#44cc44",
    config.RISK_INFO:     "#4488ff",
}

RISK_BADGE = {
    config.RISK_CRITICAL: "🔴 CRITICAL",
    config.RISK_HIGH:     "🟠 HIGH",
    config.RISK_MEDIUM:   "🟡 MEDIUM",
    config.RISK_LOW:      "🟢 LOW",
    config.RISK_INFO:     "🔵 INFO",
}


class ReportEngine:

    def __init__(self, output_dir: str = config.OUTPUT_DIR):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_all(self, scan_result, formats: List[str] = None) -> Dict[str, str]:
        """Generate all report formats. Returns dict of format→filepath."""
        if formats is None:
            formats = config.REPORT_FORMATS

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain    = self._safe_filename(scan_result.target)
        base_name = f"bughunter_{domain}_{timestamp}"

        paths = {}
        for fmt in formats:
            if fmt == "json":
                paths["json"] = self._write_json(scan_result, base_name)
            elif fmt == "html":
                paths["html"] = self._write_html(scan_result, base_name)
            elif fmt == "markdown":
                paths["markdown"] = self._write_markdown(scan_result, base_name)

        return paths

    # ─── JSON Report ─────────────────────────────────────────────────────────
    def _write_json(self, result, base_name: str) -> str:
        from core.orchestrator import ScanResult

        payload = {
            "meta": {
                "tool":        config.TOOL_NAME,
                "version":     config.VERSION,
                "generated":   datetime.now().isoformat(),
                "target":      result.target,
                "mode":        result.mode,
                "duration_s":  round(result.duration, 2),
                "total_requests": result.total_requests,
                "overall_risk": result.overall_risk,
            },
            "executive_summary": result.ai_analysis.get("executive_summary", ""),
            "immediate_action":  result.ai_analysis.get("immediate_action", ""),
            "ai_powered":        result.ai_analysis.get("ai_powered", False),
            "attack_surface": result.attack_surface,
            "findings": result.findings,
            "correlations": result.ai_analysis.get("correlations", []),
            "statistics": self._compute_stats(result.findings),
        }

        path = self.output_dir / f"{base_name}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)
        return str(path)

    # ─── HTML Report ──────────────────────────────────────────────────────────
    def _write_html(self, result, base_name: str) -> str:
        stats    = self._compute_stats(result.findings)
        findings = result.findings
        surface  = result.attack_surface

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BugHunter AI v2 — {result.target}</title>
<style>
  :root {{
    --bg: #0a0e1a; --bg2: #0f1624; --bg3: #141c2e;
    --border: #1e2d45; --accent: #00d4ff; --text: #e0e6f0;
    --text2: #8899bb; --red: #ff4444; --orange: #ff8800;
    --yellow: #ffcc00; --green: #44cc88; --blue: #4488ff;
    --purple: #8866ff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}

  /* Header */
  .header {{ background: linear-gradient(135deg, #0a0e1a 0%, #0d1928 50%, #0a1520 100%);
    border-bottom: 1px solid var(--border); padding: 32px 24px; text-align: center; }}
  .header h1 {{ font-size: 2rem; color: var(--accent); letter-spacing: 2px; }}
  .header .subtitle {{ color: var(--text2); margin-top: 8px; font-size: 0.9rem; }}
  .target-badge {{ display: inline-block; background: var(--bg3); border: 1px solid var(--border);
    border-radius: 8px; padding: 8px 20px; margin-top: 16px; color: var(--accent); font-family: monospace; font-size: 0.95rem; }}

  /* Stat cards */
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px; margin: 24px 0; }}
  .stat-card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 10px;
    padding: 20px 16px; text-align: center; transition: transform 0.2s; }}
  .stat-card:hover {{ transform: translateY(-2px); }}
  .stat-card .num {{ font-size: 2.2rem; font-weight: 700; line-height: 1; }}
  .stat-card .label {{ font-size: 0.78rem; color: var(--text2); margin-top: 6px; text-transform: uppercase; letter-spacing: 1px; }}
  .c-crit {{ color: var(--red); border-top: 3px solid var(--red); }}
  .c-high {{ color: var(--orange); border-top: 3px solid var(--orange); }}
  .c-med  {{ color: var(--yellow); border-top: 3px solid var(--yellow); }}
  .c-low  {{ color: var(--green); border-top: 3px solid var(--green); }}
  .c-info {{ color: var(--blue); border-top: 3px solid var(--blue); }}
  .c-total{{ color: var(--accent); border-top: 3px solid var(--accent); }}

  /* Section headers */
  h2 {{ font-size: 1.15rem; color: var(--accent); margin: 28px 0 14px;
    border-bottom: 1px solid var(--border); padding-bottom: 8px; }}
  h3 {{ font-size: 0.95rem; color: var(--text); margin-bottom: 8px; }}

  /* Executive summary */
  .exec-box {{ background: var(--bg2); border: 1px solid var(--border); border-left: 4px solid var(--accent);
    border-radius: 8px; padding: 18px 20px; margin-bottom: 20px; line-height: 1.7; color: var(--text2); }}

  /* Findings */
  .finding {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 10px;
    margin-bottom: 14px; overflow: hidden; }}
  .finding-header {{ padding: 14px 18px; display: flex; align-items: center; gap: 12px; cursor: pointer; }}
  .finding-header:hover {{ background: var(--bg3); }}
  .risk-badge {{ font-size: 0.72rem; font-weight: 700; padding: 3px 10px; border-radius: 12px;
    text-transform: uppercase; letter-spacing: 0.5px; white-space: nowrap; }}
  .rb-CRITICAL {{ background: rgba(255,68,68,0.2); color: var(--red); border: 1px solid var(--red); }}
  .rb-HIGH     {{ background: rgba(255,136,0,0.2); color: var(--orange); border: 1px solid var(--orange); }}
  .rb-MEDIUM   {{ background: rgba(255,204,0,0.2); color: var(--yellow); border: 1px solid var(--yellow); }}
  .rb-LOW      {{ background: rgba(68,204,136,0.2); color: var(--green); border: 1px solid var(--green); }}
  .rb-INFO     {{ background: rgba(68,136,255,0.2); color: var(--blue); border: 1px solid var(--blue); }}
  .finding-title {{ font-weight: 600; flex: 1; }}
  .finding-module {{ font-size: 0.78rem; color: var(--text2); white-space: nowrap; }}
  .finding-body {{ padding: 0 18px 16px; border-top: 1px solid var(--border); display: none; }}
  .finding.open .finding-body {{ display: block; }}
  .finding.open .finding-header {{ background: var(--bg3); }}

  .meta-row {{ display: flex; gap: 8px; align-items: center; margin: 10px 0 6px; flex-wrap: wrap; }}
  .meta-tag {{ font-size: 0.78rem; background: var(--bg3); border: 1px solid var(--border);
    border-radius: 5px; padding: 2px 8px; color: var(--text2); font-family: monospace; }}
  .conf-bar {{ height: 4px; background: var(--bg3); border-radius: 2px; margin: 8px 0; overflow: hidden; }}
  .conf-fill {{ height: 100%; border-radius: 2px; background: var(--accent); transition: width 0.4s; }}

  p.desc {{ color: var(--text2); font-size: 0.88rem; line-height: 1.6; margin: 8px 0; }}
  .evidence-box {{ background: #060a12; border: 1px solid var(--border); border-radius: 6px;
    padding: 10px 14px; font-family: monospace; font-size: 0.78rem; color: #88aacc;
    margin: 10px 0; white-space: pre-wrap; word-break: break-all; max-height: 120px; overflow-y: auto; }}
  .remedy-box {{ background: rgba(68,204,136,0.07); border: 1px solid rgba(68,204,136,0.3);
    border-radius: 6px; padding: 10px 14px; font-size: 0.85rem; color: var(--green); margin: 10px 0; }}

  /* Correlations */
  .correlation {{ background: rgba(255,136,0,0.07); border: 1px solid rgba(255,136,0,0.3);
    border-radius: 8px; padding: 14px 18px; margin-bottom: 10px; }}
  .correlation strong {{ color: var(--orange); }}

  /* Attack surface */
  .surface-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin: 12px 0; }}
  .surface-card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }}
  .surface-card .num {{ font-size: 1.8rem; font-weight: 700; color: var(--accent); }}
  .surface-card .lbl {{ font-size: 0.78rem; color: var(--text2); text-transform: uppercase; margin-top: 4px; }}

  /* Filter bar */
  .filter-bar {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }}
  .filter-btn {{ background: var(--bg3); border: 1px solid var(--border); color: var(--text2);
    padding: 5px 14px; border-radius: 20px; cursor: pointer; font-size: 0.82rem;
    transition: all 0.2s; }}
  .filter-btn:hover, .filter-btn.active {{ background: var(--accent); color: #000; border-color: var(--accent); }}

  footer {{ text-align: center; color: var(--text2); font-size: 0.78rem; margin: 40px 0 16px; }}
</style>
</head>
<body>

<div class="header">
  <h1>🔍 BugHunter AI v2</h1>
  <div class="subtitle">Security Analysis Report &nbsp;•&nbsp; {config.VERSION}</div>
  <div class="target-badge">{result.target}</div>
  <div class="subtitle" style="margin-top:10px">
    Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} &nbsp;|&nbsp;
    Duration: {result.duration:.1f}s &nbsp;|&nbsp;
    Mode: {result.mode.upper()} &nbsp;|&nbsp;
    Requests: {result.total_requests} &nbsp;|&nbsp;
    Overall Risk: <span style="color:{RISK_COLORS_HEX.get(result.overall_risk,'#fff')};font-weight:700">{result.overall_risk}</span>
  </div>
</div>

<div class="container">

  <!-- Stats -->
  <div class="stats-grid">
    <div class="stat-card c-crit"><div class="num">{stats['CRITICAL']}</div><div class="label">Critical</div></div>
    <div class="stat-card c-high"><div class="num">{stats['HIGH']}</div><div class="label">High</div></div>
    <div class="stat-card c-med"><div class="num">{stats['MEDIUM']}</div><div class="label">Medium</div></div>
    <div class="stat-card c-low"><div class="num">{stats['LOW']}</div><div class="label">Low</div></div>
    <div class="stat-card c-info"><div class="num">{stats['INFO']}</div><div class="label">Info</div></div>
    <div class="stat-card c-total"><div class="num">{len(findings)}</div><div class="label">Total</div></div>
  </div>

  <!-- Executive Summary -->
  <h2>📋 Executive Summary</h2>
  <div class="exec-box">
    {result.ai_analysis.get('executive_summary', 'Scan complete. Review findings below.')}
    {f'<br><br><strong style="color:#ffcc00">⚡ Immediate Action:</strong> {result.ai_analysis.get("immediate_action", "")}' if result.ai_analysis.get('immediate_action') else ''}
    {f'<br><span style="color:#44cc88;font-size:0.82rem">🤖 AI-Powered Analysis (Claude)</span>' if result.ai_analysis.get('ai_powered') else '<br><span style="color:#8899bb;font-size:0.82rem">📊 Local Heuristic Analysis</span>'}
  </div>

  <!-- Attack Surface -->
  <h2>🌐 Attack Surface</h2>
  <div class="surface-grid">
    <div class="surface-card"><div class="num">{len(surface.get('pages', []))}</div><div class="lbl">Pages Crawled</div></div>
    <div class="surface-card"><div class="num">{len(surface.get('forms', []))}</div><div class="lbl">Forms</div></div>
    <div class="surface-card"><div class="num">{len(surface.get('parameters', []))}</div><div class="lbl">Parameters</div></div>
    <div class="surface-card"><div class="num">{len(surface.get('api_endpoints', []))}</div><div class="lbl">API Endpoints</div></div>
    <div class="surface-card"><div class="num">{len(surface.get('js_files', []))}</div><div class="lbl">JS Files</div></div>
    <div class="surface-card"><div class="num">{len(surface.get('technologies', []))}</div><div class="lbl">Technologies</div></div>
  </div>
  {f'<p class="desc">Technologies: {", ".join(list(surface.get("technologies", []))[:10]) or "None detected"}</p>' if surface.get('technologies') else ''}

  <!-- Correlations -->
  {self._html_correlations(result.ai_analysis.get('correlations', []))}

  <!-- Findings -->
  <h2>🔍 Findings ({len(findings)})</h2>

  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterFindings('ALL')">All ({len(findings)})</button>
    <button class="filter-btn" onclick="filterFindings('CRITICAL')" style="color:#ff4444">Critical ({stats['CRITICAL']})</button>
    <button class="filter-btn" onclick="filterFindings('HIGH')" style="color:#ff8800">High ({stats['HIGH']})</button>
    <button class="filter-btn" onclick="filterFindings('MEDIUM')" style="color:#ffcc00">Medium ({stats['MEDIUM']})</button>
    <button class="filter-btn" onclick="filterFindings('LOW')" style="color:#44cc88">Low ({stats['LOW']})</button>
  </div>

  <div id="findings-container">
    {self._html_findings(findings)}
  </div>

</div>

<footer>
  BugHunter AI v2 &nbsp;•&nbsp; For authorized security testing only &nbsp;•&nbsp; {datetime.now().year}
</footer>

<script>
function filterFindings(level) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding').forEach(f => {{
    f.style.display = (level === 'ALL' || f.dataset.risk === level) ? '' : 'none';
  }});
}}
document.querySelectorAll('.finding-header').forEach(h => {{
  h.addEventListener('click', () => h.parentElement.classList.toggle('open'));
}});
// Auto-expand critical findings
document.querySelectorAll('.finding[data-risk="CRITICAL"], .finding[data-risk="HIGH"]').forEach(f => {{
  f.classList.add('open');
}});
</script>
</body></html>"""

        path = self.output_dir / f"{base_name}.html"
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return str(path)

    def _html_findings(self, findings: List[Dict]) -> str:
        if not findings:
            return '<p style="color:#8899bb;text-align:center;padding:30px">No findings detected.</p>'
        out = []
        for i, f in enumerate(findings):
            risk      = f.get("risk", "INFO")
            conf      = f.get("confidence", 50)
            evidence  = f.get("evidence", "")[:400]
            remedy    = f.get("remedy", "")
            ai_reason = f.get("ai_reasoning", "")
            pfix      = f.get("priority_fix", "")

            out.append(f"""
<div class="finding" data-risk="{risk}" id="f{i}">
  <div class="finding-header">
    <span class="risk-badge rb-{risk}">{risk}</span>
    <span class="finding-title">{self._esc(f.get('title',''))}</span>
    <span class="finding-module">{f.get('module','')}</span>
  </div>
  <div class="finding-body">
    <div class="meta-row">
      <span class="meta-tag">🔗 {self._esc(f.get('url','')[:80])}</span>
      <span class="meta-tag">📊 Confidence: {conf}%</span>
      <span class="meta-tag">🔢 Signals: {f.get('num_signals',1)}</span>
    </div>
    <div class="conf-bar"><div class="conf-fill" style="width:{conf}%"></div></div>
    <p class="desc">{self._esc(f.get('description',''))}</p>
    {f'<div class="evidence-box">{self._esc(evidence)}</div>' if evidence else ''}
    {f'<div class="remedy-box">💡 <strong>Fix:</strong> {self._esc(remedy)}</div>' if remedy else ''}
    {f'<p class="desc" style="color:#8866ff"><strong>🤖 AI Reasoning:</strong> {self._esc(ai_reason)}</p>' if ai_reason else ''}
    {f'<p class="desc" style="color:#44cc88"><strong>⚡ Priority Fix:</strong> {self._esc(pfix)}</p>' if pfix else ''}
  </div>
</div>""")
        return "\n".join(out)

    def _html_correlations(self, correlations: List[Dict]) -> str:
        if not correlations:
            return ""
        items = []
        for c in correlations:
            items.append(f"""
<div class="correlation">
  <strong>⚡ Compound Risk [{c.get('combined_risk','HIGH')}]:</strong>
  {self._esc(c.get('finding_1',''))} + {self._esc(c.get('finding_2',''))}
  <br><span style="color:#ccaa88;font-size:0.85rem">{self._esc(c.get('reasoning',''))}</span>
</div>""")
        return f"<h2>⚡ Risk Correlations ({len(correlations)})</h2>\n" + "\n".join(items)

    # ─── Markdown Report ──────────────────────────────────────────────────────
    def _write_markdown(self, result, base_name: str) -> str:
        stats = self._compute_stats(result.findings)
        lines = [
            f"# 🔍 BugHunter AI v2 — Security Report",
            f"",
            f"**Target:** `{result.target}`  ",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
            f"**Duration:** {result.duration:.1f}s  ",
            f"**Mode:** {result.mode.upper()}  ",
            f"**Overall Risk:** **{result.overall_risk}**  ",
            f"**Total Requests:** {result.total_requests}",
            f"",
            f"---",
            f"",
            f"## 📋 Executive Summary",
            f"",
            result.ai_analysis.get("executive_summary", "Scan complete."),
            f"",
        ]

        if result.ai_analysis.get("immediate_action"):
            lines += [f"> ⚡ **Immediate Action:** {result.ai_analysis['immediate_action']}", ""]

        # Stats table
        lines += [
            f"## 📊 Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]
        for level in [config.RISK_CRITICAL, config.RISK_HIGH, config.RISK_MEDIUM, config.RISK_LOW, config.RISK_INFO]:
            icon = RISK_BADGE[level]
            lines.append(f"| {icon} | {stats[level]} |")
        lines += [f"| **TOTAL** | **{len(result.findings)}** |", ""]

        # Attack surface
        surface = result.attack_surface
        lines += [
            f"## 🌐 Attack Surface",
            f"",
            f"- Pages crawled: {len(surface.get('pages', []))}",
            f"- Forms: {len(surface.get('forms', []))}",
            f"- Parameters: {len(surface.get('parameters', []))}",
            f"- API Endpoints: {len(surface.get('api_endpoints', []))}",
            f"- JavaScript Files: {len(surface.get('js_files', []))}",
            f"- Technologies: {', '.join(list(surface.get('technologies', []))[:8]) or 'None detected'}",
            f"",
        ]

        # Correlations
        correlations = result.ai_analysis.get("correlations", [])
        if correlations:
            lines += [f"## ⚡ Risk Correlations", ""]
            for c in correlations:
                lines += [
                    f"### [{c.get('combined_risk','HIGH')}] {c.get('finding_1','')} + {c.get('finding_2','')}",
                    f"{c.get('reasoning','')}",
                    "",
                ]

        # Findings
        lines += [f"## 🔍 Findings ({len(result.findings)})", ""]
        for i, f in enumerate(result.findings, 1):
            lines += [
                f"### {i}. [{f.get('risk','INFO')}] {f.get('title','')}",
                f"",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| **Module** | {f.get('module','')} |",
                f"| **URL** | `{f.get('url','')}` |",
                f"| **Risk** | {f.get('risk','')} |",
                f"| **Confidence** | {f.get('confidence',0)}% |",
                f"",
                f"**Description:** {f.get('description','')}",
                f"",
            ]
            if f.get("evidence"):
                lines += [f"**Evidence:**", f"```", f.get('evidence','')[:300], f"```", ""]
            if f.get("remedy"):
                lines += [f"**Fix:** {f.get('remedy','')}", ""]
            if f.get("ai_reasoning"):
                lines += [f"**AI Reasoning:** {f.get('ai_reasoning','')}", ""]
            lines.append("---")

        lines += [
            "",
            f"*Report generated by {config.TOOL_NAME} v{config.VERSION}*",
            f"*For authorized security testing only*",
        ]

        path = self.output_dir / f"{base_name}.md"
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return str(path)

    # ─── Helpers ─────────────────────────────────────────────────────────────
    def _compute_stats(self, findings: List[Dict]) -> Dict[str, int]:
        stats = {config.RISK_CRITICAL: 0, config.RISK_HIGH: 0,
                 config.RISK_MEDIUM: 0, config.RISK_LOW: 0, config.RISK_INFO: 0}
        for f in findings:
            stats[f.get("risk", config.RISK_INFO)] = stats.get(f.get("risk", config.RISK_INFO), 0) + 1
        return stats

    def _safe_filename(self, url: str) -> str:
        import re
        clean = re.sub(r'https?://', '', url)
        clean = re.sub(r'[^\w\-]', '_', clean)
        return clean[:40]

    def _esc(self, s: str) -> str:
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
