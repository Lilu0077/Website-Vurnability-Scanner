#!/usr/bin/env python3
"""
BugHunter AI v2 - Main CLI Entry Point
AI-Powered Web Security Analysis Platform

Usage:
    python main.py <target> [options]

Examples:
    python main.py https://example.com
    python main.py https://example.com --mode active
    python main.py https://example.com --mode passive --max-pages 50 --output json,html
"""

import sys
import os
import argparse
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from cli_output import (
    console, print_banner, print_section, print_info, print_success,
    print_warning, print_error, print_finding, print_attack_surface,
    print_scan_summary, print_module_status, get_progress_bar, confirm_scan
)
from orchestrator import Orchestrator
from report_engine import ReportEngine
from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog        = "bughunter",
        description = "BugHunter AI v2 — AI-Powered Web Security Analysis Platform",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = """
Examples:
  python main.py https://example.com
  python main.py https://target.com --mode active --max-pages 100
  python main.py https://api.target.com --mode passive --output json,html,markdown
  python main.py https://target.com --delay 1.0 --timeout 20 --no-verify-ssl

⚠  AUTHORIZED TARGETS ONLY. Unauthorized scanning is illegal.
        """
    )

    parser.add_argument("target", help="Target URL (e.g. https://example.com)")

    parser.add_argument(
        "--mode", choices=["passive", "active"], default="passive",
        help="Scan mode: passive (default, safe analysis) or active (safe probing)"
    )
    parser.add_argument(
        "--max-pages", type=int, default=config.DEFAULT_MAX_PAGES,
        help=f"Maximum pages to crawl (default: {config.DEFAULT_MAX_PAGES})"
    )
    parser.add_argument(
        "--max-depth", type=int, default=config.DEFAULT_MAX_DEPTH,
        help=f"Maximum crawl depth (default: {config.DEFAULT_MAX_DEPTH})"
    )
    parser.add_argument(
        "--delay", type=float, default=config.DEFAULT_DELAY,
        help=f"Delay between requests in seconds (default: {config.DEFAULT_DELAY})"
    )
    parser.add_argument(
        "--timeout", type=int, default=config.DEFAULT_TIMEOUT,
        help=f"HTTP request timeout (default: {config.DEFAULT_TIMEOUT}s)"
    )
    parser.add_argument(
        "--no-verify-ssl", action="store_true", default=False,
        help="Disable SSL certificate verification"
    )
    parser.add_argument(
        "--proxy", default=None,
        help="HTTP proxy URL (e.g. http://127.0.0.1:8080 for Burp Suite)"
    )
    parser.add_argument(
        "--output", default="json,html,markdown",
        help="Report formats (comma-separated): json,html,markdown (default: all)"
    )
    parser.add_argument(
        "--output-dir", default=config.OUTPUT_DIR,
        help=f"Output directory for reports (default: {config.OUTPUT_DIR})"
    )
    parser.add_argument(
        "--no-confirm", action="store_true", default=False,
        help="Skip authorization confirmation (use only if you're sure)"
    )
    parser.add_argument(
        "--quiet", action="store_true", default=False,
        help="Suppress detailed output, show summary only"
    )

    return parser


def validate_target(target: str) -> str:
    """Validate and normalize the target URL."""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    if not target.replace("https://", "").replace("http://", "").strip():
        print_error("Invalid target URL")
        sys.exit(1)
    return target.rstrip("/")


def run_scan(args) -> int:
    """Execute the full scan. Returns exit code."""

    print_banner()

    target = validate_target(args.target)

    # ── Authorization confirmation ─────────────────────────────────────────
    if not args.no_confirm and config.REQUIRE_CONFIRMATION:
        if not confirm_scan(target, args.mode):
            console.print()
            print_warning("Scan cancelled. Only scan systems you have explicit authorization to test.")
            return 1

    # ── Scan configuration ─────────────────────────────────────────────────
    print_section("SCAN CONFIGURATION", "⚙")
    print_info(f"Target:     {target}")
    print_info(f"Mode:       {args.mode.upper()}")
    print_info(f"Max Pages:  {args.max_pages}")
    print_info(f"Max Depth:  {args.max_depth}")
    print_info(f"Delay:      {args.delay}s between requests")
    print_info(f"AI Engine:  {'Claude API ✓' if config.AI_ENABLED else 'Local Heuristics (set ANTHROPIC_API_KEY for Claude)'}")

    if args.mode == config.MODE_ACTIVE:
        print_warning("Active mode: safe probes will be sent to detect anomalies.")
        print_warning("Ensure you have explicit written authorization for the target.")

    # ── Module status display ──────────────────────────────────────────────
    events_log = []

    def progress_callback(event_type, *args):
        events_log.append((event_type, args))
        if event_type == "phase":
            phase_name, phase_msg = args[0], args[1]
            print_section(f"{phase_name}: {phase_msg}")
        elif event_type == "module_start":
            print_module_status(args[0], "running")
        elif event_type == "module_done":
            name, count = args[0], args[1]
            status = "done"
            if count > 0:
                console.print(f"    [bold green]✓[/bold green] {name} — [{count} finding(s)]", highlight=False)
            else:
                console.print(f"    [dim]✓[/dim] [dim]{name}[/dim]")
        elif event_type == "module_error":
            print_error(f"{args[0]}: {args[1]}")
        elif event_type == "adaptive":
            print_info(f"[AI] {args[0]}")
        elif event_type == "crawl_progress":
            pass  # Handled by progress bar

    # ── Run orchestrator ───────────────────────────────────────────────────
    orchestrator = Orchestrator(
        target      = target,
        mode        = args.mode,
        max_pages   = args.max_pages,
        max_depth   = args.max_depth,
        timeout     = args.timeout,
        delay       = args.delay,
        verify_ssl  = not args.no_verify_ssl,
        proxy       = args.proxy,
        progress_cb = progress_callback,
    )

    result = orchestrator.run()

    # ── Display attack surface ─────────────────────────────────────────────
    if not args.quiet and result.attack_surface:
        print_section("ATTACK SURFACE MAP", "🌐")
        print_attack_surface(result.attack_surface)

    # ── Display findings ───────────────────────────────────────────────────
    if not args.quiet and result.findings:
        print_section("FINDINGS", "🔍")
        for finding in result.findings:
            print_finding(finding)

    elif not result.findings:
        print_section("FINDINGS", "🔍")
        console.print("  [bold green]✓[/bold green] No issues detected in this scan.")

    # ── AI Analysis correlations ───────────────────────────────────────────
    correlations = result.ai_analysis.get("correlations", [])
    if correlations:
        print_section("AI RISK CORRELATIONS", "⚡")
        from rich.panel import Panel
        from rich import box
        for c in correlations:
            risk_color = "bold yellow" if c.get("combined_risk") == "HIGH" else "bold red"
            console.print(Panel(
                f"[{risk_color}]{c.get('finding_1','')}[/{risk_color}] + [{risk_color}]{c.get('finding_2','')}[/{risk_color}]\n"
                f"[dim]{c.get('reasoning','')}[/dim]",
                title=f"[{risk_color}]Combined Risk: {c.get('combined_risk','HIGH')}[/{risk_color}]",
                border_style="yellow",
                box=box.ROUNDED,
            ))

    # ── Scan summary ───────────────────────────────────────────────────────
    print_scan_summary(result.findings, result.duration, target)

    # ── Error handling ─────────────────────────────────────────────────────
    if result.error:
        print_error(f"Scan error: {result.error}")

    # ── Generate reports ───────────────────────────────────────────────────
    formats = [f.strip() for f in args.output.split(",") if f.strip()]
    report_engine = ReportEngine(output_dir=args.output_dir)

    print_section("REPORTS", "📊")
    try:
        report_paths = report_engine.generate_all(result, formats=formats)
        for fmt, path in report_paths.items():
            print_success(f"{fmt.upper()} report: {path}")
    except Exception as e:
        print_error(f"Report generation failed: {e}")

    # ── Stats footer ───────────────────────────────────────────────────────
    console.print()
    console.print(
        f"  [dim]Total HTTP requests: {result.total_requests} | "
        f"Scan time: {result.duration:.1f}s | "
        f"AI: {'Claude' if result.ai_analysis.get('ai_powered') else 'Local Heuristics'}[/dim]"
    )
    console.print()

    # Return non-zero exit code if critical/high findings
    from config import RISK_CRITICAL, RISK_HIGH
    critical_count = sum(1 for f in result.findings if f.get("risk") in (RISK_CRITICAL, RISK_HIGH))
    return 2 if critical_count > 0 else 0


def main():
    parser = build_parser()

    if len(sys.argv) == 1:
        print_banner()
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    try:
        exit_code = run_scan(args)
        sys.exit(exit_code)
    except KeyboardInterrupt:
        console.print()
        print_warning("Scan interrupted.")
        sys.exit(1)


if __name__ == "__main__":
    main()
