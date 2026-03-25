"""
BugHunter AI v2 - Intelligent Crawler
Full attack surface discovery: pages, forms, parameters, APIs, JS endpoints.
"""

import re
import json
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import Set, List, Dict, Optional
from collections import deque
from dataclasses import dataclass, field

from bs4 import BeautifulSoup
import tldextract

import config
from core.http_client import HttpClient, HttpResponse
from utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class AttackSurface:
    base_url:      str
    pages:         Set[str]         = field(default_factory=set)
    forms:         List[Dict]       = field(default_factory=list)
    parameters:    Set[str]         = field(default_factory=set)
    api_endpoints: List[str]        = field(default_factory=list)
    js_files:      Set[str]         = field(default_factory=set)
    external_links: Set[str]        = field(default_factory=set)
    technologies:  Set[str]         = field(default_factory=set)
    cookies:       Dict[str, Dict]  = field(default_factory=dict)
    headers:       Dict[str, str]   = field(default_factory=dict)
    critical_endpoints: List[str]   = field(default_factory=list)
    response_codes: Dict[str, int]  = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "base_url":          self.base_url,
            "pages":             list(self.pages),
            "forms":             self.forms,
            "parameters":        list(self.parameters),
            "api_endpoints":     self.api_endpoints,
            "js_files":          list(self.js_files),
            "external_links":    list(self.external_links),
            "technologies":      list(self.technologies),
            "critical_endpoints": self.critical_endpoints,
            "response_codes":    self.response_codes,
            "stats": {
                "total_pages":   len(self.pages),
                "total_forms":   len(self.forms),
                "total_params":  len(self.parameters),
                "total_apis":    len(self.api_endpoints),
                "total_js":      len(self.js_files),
            }
        }


# Patterns that suggest API or sensitive endpoints
API_PATTERNS = re.compile(
    r'(?:\'|")((?:/api/|/v\d+/|/rest/|/graphql|/ajax/|/json/|/data/|/endpoint|/service)'
    r'[^\'"\s<>]{0,200})(?:\'|")', re.IGNORECASE
)

# JavaScript URL extraction
JS_URL_PATTERNS = re.compile(
    r'''(?:fetch|axios|http\.get|http\.post|XHR|XMLHttpRequest|ajax|url)\s*[\(=:,]\s*['"` ]'''
    r'''((?:https?://[^\s'"` ]{1,300}|/[a-zA-Z0-9_/\-\.?=&]{1,200}))''',
    re.IGNORECASE,
)

# Critical endpoint patterns (prioritized in scan)
CRITICAL_PATH_PATTERNS = [
    r'/admin', r'/login', r'/logout', r'/signup', r'/register',
    r'/password', r'/reset', r'/forgot', r'/account', r'/profile',
    r'/settings', r'/api', r'/dashboard', r'/upload', r'/export',
    r'/delete', r'/auth', r'/token', r'/oauth', r'/payment', r'/checkout',
    r'/graphql', r'/config', r'/env', r'\.env', r'/debug', r'/test',
    r'/backup', r'/phpinfo', r'/\.git', r'/swagger', r'/openapi',
    r'/actuator', r'/metrics', r'/health', r'/status',
]


class IntelligentCrawler:
    """
    Autonomous web crawler that maps the full attack surface.
    Uses BFS with intelligent deduplication and loop detection.
    """

    def __init__(
        self,
        client:    HttpClient,
        base_url:  str,
        max_pages: int = config.DEFAULT_MAX_PAGES,
        max_depth: int = config.DEFAULT_MAX_DEPTH,
    ):
        self.client    = client
        self.base_url  = base_url.rstrip("/")
        self.max_pages = max_pages
        self.max_depth = max_depth

        parsed = urlparse(base_url)
        self.base_domain = parsed.netloc
        self.base_scheme = parsed.scheme

        ext = tldextract.extract(base_url)
        self.root_domain = f"{ext.domain}.{ext.suffix}"

        self.surface    = AttackSurface(base_url=base_url)
        self._visited:  Set[str] = set()
        self._queue:    deque    = deque()

    # ─── Main Crawl Entry ──────────────────────────────────────────────────────
    def crawl(self, progress_callback=None) -> AttackSurface:
        log.info(f"Starting crawl: {self.base_url}")
        self._queue.append((self.base_url, 0))
        self._visited.add(self._normalize(self.base_url))

        while self._queue and len(self.surface.pages) < self.max_pages:
            url, depth = self._queue.popleft()

            if depth > self.max_depth:
                continue

            resp = self.client.get(url)
            if not resp.ok:
                self.surface.response_codes[url] = resp.status_code
                continue

            self.surface.pages.add(url)
            self.surface.response_codes[url] = resp.status_code

            # Capture headers from base URL
            if url == self.base_url:
                self.surface.headers = resp.headers
                self.surface.cookies = self._extract_cookies(resp)

            # Parse HTML if applicable
            if resp.is_html:
                self._parse_html(resp, url, depth)

            # Parse JS files
            if "javascript" in resp.content_type or url.endswith(".js"):
                self._parse_js(resp.text, url)

            # Classify as critical
            self._classify_critical(url)

            if progress_callback:
                progress_callback(len(self.surface.pages))

        # Post-process: extract parameters from all pages
        self._extract_all_parameters()

        log.info(
            f"Crawl complete: {len(self.surface.pages)} pages, "
            f"{len(self.surface.forms)} forms, {len(self.surface.api_endpoints)} APIs"
        )
        return self.surface

    # ─── HTML Parser ──────────────────────────────────────────────────────────
    def _parse_html(self, resp: HttpResponse, base: str, depth: int):
        try:
            soup = BeautifulSoup(resp.text, "lxml")
        except Exception:
            soup = BeautifulSoup(resp.text, "html.parser")

        # Extract <a> links
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            full = self._resolve(href, base)
            if full and self._is_internal(full):
                norm = self._normalize(full)
                if norm not in self._visited and len(self.surface.pages) < self.max_pages:
                    self._visited.add(norm)
                    self._queue.append((full, depth + 1))

        # Extract forms
        for form in soup.find_all("form"):
            form_data = self._parse_form(form, base)
            if form_data:
                self.surface.forms.append(form_data)

        # Extract <script src=...>
        for script in soup.find_all("script", src=True):
            js_url = self._resolve(script["src"], base)
            if js_url and self._is_internal(js_url):
                self.surface.js_files.add(js_url)
                norm = self._normalize(js_url)
                if norm not in self._visited:
                    self._visited.add(norm)
                    self._queue.append((js_url, depth + 1))

        # Extract inline <script> for API endpoints
        for script in soup.find_all("script"):
            if script.string:
                self._parse_js(script.string, base)

        # Extract Next.js __NEXT_DATA__
        next_data = soup.find("script", id="__NEXT_DATA__")
        if next_data and next_data.string:
            self._extract_nextjs_routes(next_data.string)

        # Extract external links (for CORS / third-party analysis)
        for tag in soup.find_all(["a", "link", "script", "img"], src=True):
            src = tag.get("src") or tag.get("href", "")
            if src.startswith("http") and not self._is_internal(src):
                self.surface.external_links.add(src[:200])

        # Technology detection from HTML
        self._detect_tech_from_html(resp.text)

    # ─── JavaScript Parser ────────────────────────────────────────────────────
    def _parse_js(self, js_content: str, base_url: str):
        """Extract API endpoints from JavaScript source."""
        # API path patterns
        for match in API_PATTERNS.finditer(js_content):
            path = match.group(1)
            full = self._resolve(path, base_url) or path
            if full not in self.surface.api_endpoints:
                self.surface.api_endpoints.append(full)

        # fetch/axios/XHR patterns
        for match in JS_URL_PATTERNS.finditer(js_content):
            url = match.group(1).strip()
            if url.startswith("/"):
                full = f"{self.base_scheme}://{self.base_domain}{url}"
            elif url.startswith("http"):
                full = url
            else:
                continue
            if self._is_internal(full) and full not in self.surface.api_endpoints:
                self.surface.api_endpoints.append(full)

        # GraphQL detection
        if re.search(r'(graphql|gql|__typename)', js_content, re.I):
            gql_url = f"{self.base_url}/graphql"
            if gql_url not in self.surface.api_endpoints:
                self.surface.api_endpoints.append(gql_url)

    # ─── Form Parser ──────────────────────────────────────────────────────────
    def _parse_form(self, form_tag, base_url: str) -> Optional[Dict]:
        action = form_tag.get("action", "")
        method = form_tag.get("method", "GET").upper()
        full_action = self._resolve(action, base_url) or base_url

        inputs = []
        for inp in form_tag.find_all(["input", "textarea", "select"]):
            inp_type = inp.get("type", "text").lower()
            inp_name = inp.get("name", "")
            if inp_name:
                inputs.append({
                    "name":  inp_name,
                    "type":  inp_type,
                    "value": inp.get("value", ""),
                })
                self.surface.parameters.add(inp_name)

        if not inputs and not full_action:
            return None

        # Detect CSRF token presence
        csrf_field = any(
            re.search(r'csrf|_token|authenticity_token|__requestverificationtoken',
                      i.get("name", ""), re.I)
            for i in inputs
        )

        return {
            "action":      full_action,
            "method":      method,
            "inputs":      inputs,
            "csrf_token":  csrf_field,
            "enctype":     form_tag.get("enctype", "application/x-www-form-urlencoded"),
        }

    # ─── Next.js Route Extraction ─────────────────────────────────────────────
    def _extract_nextjs_routes(self, json_text: str):
        try:
            data = json.loads(json_text)
            pages = data.get("buildManifest", {}).get("pages", [])
            for page in pages:
                if isinstance(page, str):
                    url = f"{self.base_url}{page}"
                    if url not in self.surface.api_endpoints:
                        self.surface.api_endpoints.append(url)
        except Exception:
            pass

    # ─── Technology Detection ─────────────────────────────────────────────────
    def _detect_tech_from_html(self, html: str):
        for tech, signatures in config.TECH_SIGNATURES.items():
            if any(sig.lower() in html.lower() for sig in signatures):
                self.surface.technologies.add(tech)

    # ─── Critical Endpoint Classifier ─────────────────────────────────────────
    def _classify_critical(self, url: str):
        for pattern in CRITICAL_PATH_PATTERNS:
            if re.search(pattern, url, re.I):
                if url not in self.surface.critical_endpoints:
                    self.surface.critical_endpoints.append(url)
                break

    # ─── Parameter Extraction ─────────────────────────────────────────────────
    def _extract_all_parameters(self):
        """Extract query parameters from all discovered URLs."""
        for url in self.surface.pages | set(self.surface.api_endpoints):
            parsed = urlparse(url)
            for param in parse_qs(parsed.query).keys():
                self.surface.parameters.add(param)

    # ─── Cookie Extraction ────────────────────────────────────────────────────
    def _extract_cookies(self, resp: HttpResponse) -> Dict[str, Dict]:
        cookies = {}
        set_cookie = resp.headers.get("Set-Cookie", "")
        if set_cookie:
            # Simple parse — we rely on the session cookies too
            for cookie_str in set_cookie.split(","):
                parts = [p.strip() for p in cookie_str.split(";")]
                if parts:
                    name_val = parts[0].split("=", 1)
                    if len(name_val) == 2:
                        name, val = name_val
                        cookies[name] = {
                            "value":    val,
                            "secure":   "Secure" in parts,
                            "httponly": "HttpOnly" in parts,
                            "samesite": next((p.split("=")[1] for p in parts if p.lower().startswith("samesite")), None),
                            "path":     next((p.split("=")[1] for p in parts if p.lower().startswith("path")), "/"),
                        }
        # Also grab from session
        for name, val in self.client.session.cookies.items():
            if name not in cookies:
                cookies[name] = {"value": val, "secure": None, "httponly": None, "samesite": None}
        return cookies

    # ─── URL Helpers ──────────────────────────────────────────────────────────
    def _resolve(self, href: str, base: str) -> Optional[str]:
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
            return None
        try:
            return urljoin(base, href).split("#")[0]
        except Exception:
            return None

    def _is_internal(self, url: str) -> bool:
        try:
            ext = tldextract.extract(url)
            return f"{ext.domain}.{ext.suffix}" == self.root_domain
        except Exception:
            return False

    def _normalize(self, url: str) -> str:
        """Normalize URL for deduplication."""
        p = urlparse(url)
        # Sort query params for canonical form
        params = sorted(parse_qs(p.query).items())
        norm_query = urlencode(params, doseq=True)
        return f"{p.scheme}://{p.netloc}{p.path}?{norm_query}".rstrip("?")
