"""
BugHunter AI v2 - Central Orchestrator
Coordinates crawler, modules, AI engine, and reporting.
Implements intelligent adaptive scan strategy.
"""

import time
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field

import config
from core.http_client import HttpClient
from core.crawler import IntelligentCrawler, AttackSurface
from core.ai_engine import AIEngine
from core.risk_scorer import RiskScorer
from utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class ScanResult:
    target:          str
    mode:            str
    start_time:      float
    end_time:        float        = 0.0
    attack_surface:  Dict         = field(default_factory=dict)
    findings:        List[Dict]   = field(default_factory=list)
    ai_analysis:     Dict         = field(default_factory=dict)
    overall_risk:    str          = config.RISK_INFO
    total_requests:  int          = 0
    error:           Optional[str]= None

    @property
    def duration(self) -> float:
        return (self.end_time or time.time()) - self.start_time


class Orchestrator:
    """
    Central scan orchestrator.
    Manages module execution, adaptive strategy, and result aggregation.
    """

    def __init__(
        self,
        target:      str,
        mode:        str   = config.MODE_PASSIVE,
        max_pages:   int   = config.DEFAULT_MAX_PAGES,
        max_depth:   int   = config.DEFAULT_MAX_DEPTH,
        timeout:     int   = config.DEFAULT_TIMEOUT,
        delay:       float = config.DEFAULT_DELAY,
        verify_ssl:  bool  = True,
        proxy:       Optional[str] = None,
        progress_cb: Optional[Callable] = None,
    ):
        self.target      = target.rstrip("/")
        self.mode        = mode
        self.progress_cb = progress_cb

        self.client = HttpClient(
            timeout    = timeout,
            delay      = delay,
            verify_ssl = verify_ssl,
            proxy      = proxy,
        )
        self.ai_engine  = AIEngine()
        self.risk_scorer = RiskScorer()

        self.max_pages = max_pages
        self.max_depth = max_depth

        # Track which modules were skipped and why (adaptive strategy)
        self._skipped_modules: Dict[str, str] = {}
        self._module_timings:  Dict[str, float] = {}

    # ─── Main Scan Entry ──────────────────────────────────────────────────────
    def run(self) -> ScanResult:
        result = ScanResult(
            target     = self.target,
            mode       = self.mode,
            start_time = time.time(),
        )

        try:
            self._emit("phase", "CRAWL", "Discovering attack surface...")
            surface = self._run_crawl()
            result.attack_surface = surface.to_dict()

            self._emit("phase", "ANALYZE", f"Running {self._count_modules(surface)} detection modules...")
            findings = self._run_modules(surface)

            self._emit("phase", "AI", "Running AI analysis and correlation...")
            ai_result = self.ai_engine.analyze_findings(
                findings       = findings,
                attack_surface = result.attack_surface,
                target         = self.target,
            )

            # Merge AI enrichment into findings
            findings = ai_result.get("enriched_findings", findings)

            # Score and prioritize
            findings = self.risk_scorer.prioritize_findings(findings)

            result.findings       = findings
            result.ai_analysis    = ai_result
            result.overall_risk   = self.risk_scorer.compute_overall_risk(findings)
            result.total_requests = self.client.request_count
            result.end_time       = time.time()

        except KeyboardInterrupt:
            result.error    = "Scan interrupted by user"
            result.end_time = time.time()
        except Exception as e:
            log.error(f"Orchestrator error: {e}", exc_info=True)
            result.error    = str(e)
            result.end_time = time.time()

        return result

    # ─── Crawl Phase ──────────────────────────────────────────────────────────
    def _run_crawl(self) -> AttackSurface:
        crawler = IntelligentCrawler(
            client    = self.client,
            base_url  = self.target,
            max_pages = self.max_pages,
            max_depth = self.max_depth,
        )

        def crawl_progress(page_count):
            self._emit("crawl_progress", page_count)

        return crawler.crawl(progress_callback=crawl_progress)

    # ─── Module Execution Phase ───────────────────────────────────────────────
    def _run_modules(self, surface: AttackSurface) -> List[Dict]:
        all_findings: List[Dict] = []
        surface_dict = surface.to_dict()
        techs        = surface.technologies

        # ── Build adaptive module list ────────────────────────────────────────
        modules = self._build_module_list(surface)

        for module_name, module_fn, module_kwargs in modules:
            self._emit("module_start", module_name)
            t0 = time.time()

            try:
                findings = module_fn(
                    client  = self.client,
                    url     = self.target,
                    surface = surface_dict,
                    mode    = self.mode,
                    **module_kwargs,
                )
                all_findings.extend(findings or [])
                elapsed = time.time() - t0
                self._module_timings[module_name] = elapsed
                self._emit("module_done", module_name, len(findings or []))

            except Exception as e:
                log.warning(f"Module {module_name} failed: {e}")
                self._emit("module_error", module_name, str(e))

        return all_findings

    # ─── Adaptive Module Builder ───────────────────────────────────────────────
    def _build_module_list(self, surface: AttackSurface) -> list:
        """
        Intelligently decide which modules to run based on detected surface.
        This is the core of the adaptive scanning strategy.
        """
        from modules import (
            header_analyzer, tech_fingerprint, xss_detector,
            sqli_detector, cors_analyzer, cookie_analyzer,
            info_disclosure, csrf_detector, api_analyzer,
        )
        from modules.redirect_ssl_cj import (
            analyze_redirect, analyze_ssl, analyze_clickjacking
        )
        from modules.csrf_detector import analyze_csrf

        techs   = surface.technologies
        has_api = len(surface.api_endpoints) > 0
        has_forms = len(surface.forms) > 0

        # Always-on modules (passive intelligence)
        modules = [
            ("Security Headers",    header_analyzer.analyze,      {}),
            ("Tech Fingerprint",    tech_fingerprint.analyze,     {}),
            ("SSL/TLS Analysis",    analyze_ssl,                  {}),
            ("Clickjacking",        analyze_clickjacking,         {}),
            ("Information Disclosure", info_disclosure.analyze,   {}),
            ("Cookie Security",     cookie_analyzer.analyze,      {}),
        ]

        # CORS — always relevant
        modules.append(("CORS Analyzer", cors_analyzer.analyze, {}))

        # XSS — always relevant if pages exist
        if surface.pages:
            modules.append(("XSS Detection", xss_detector.analyze, {}))

        # SQLi — relevant if parameters or forms exist
        if surface.parameters or surface.forms:
            modules.append(("SQLi Detection", sqli_detector.analyze, {}))

        # CSRF — relevant only if forms exist (adaptive skip)
        if has_forms:
            modules.append(("CSRF Detection", analyze_csrf, {}))
        else:
            self._skipped_modules["CSRF Detection"] = "No POST forms detected"

        # API analysis — only if API endpoints found (adaptive)
        if has_api:
            modules.append(("API Security", api_analyzer.analyze, {}))
        else:
            self._skipped_modules["API Security"] = "No API endpoints discovered"

        # Open redirect — relevant if redirect params detected
        modules.append(("Open Redirect", analyze_redirect, {}))

        # GraphQL — only if GraphQL detected
        if "GraphQL" in techs:
            self._emit("adaptive", "GraphQL detected — adding GraphQL introspection checks")
        elif not any("/graphql" in u for u in surface.api_endpoints):
            self._skipped_modules["GraphQL Checks"] = "No GraphQL endpoints found"

        return modules

    def _count_modules(self, surface: AttackSurface) -> int:
        return len(self._build_module_list(surface))

    # ─── Event Emitter ────────────────────────────────────────────────────────
    def _emit(self, event_type: str, *args):
        if self.progress_cb:
            self.progress_cb(event_type, *args)
