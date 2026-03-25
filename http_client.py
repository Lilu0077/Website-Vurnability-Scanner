"""
BugHunter AI v2 - HTTP Client
Safe, rate-limited HTTP client with fingerprinting support.
"""

import time
import requests
import urllib3
from urllib.parse import urljoin, urlparse
from typing import Optional, Dict, Any
from dataclasses import dataclass, field

import config
from utils.logger import get_logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = get_logger(__name__)


@dataclass
class HttpResponse:
    url:             str
    status_code:     int
    headers:         Dict[str, str]
    text:            str
    elapsed_ms:      float
    redirect_chain:  list = field(default_factory=list)
    error:           Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status_code < 500

    @property
    def content_type(self) -> str:
        return self.headers.get("Content-Type", "")

    @property
    def is_json(self) -> bool:
        return "json" in self.content_type.lower()

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type.lower()

    @property
    def size_bytes(self) -> int:
        return len(self.text.encode("utf-8", errors="replace"))


class HttpClient:
    """
    Safe, rate-limited HTTP client for BugHunter AI.
    All requests are read-only unless explicitly operating in
    active mode with explicit parameters.
    """

    def __init__(
        self,
        timeout:    int   = config.DEFAULT_TIMEOUT,
        delay:      float = config.DEFAULT_DELAY,
        user_agent: str   = config.DEFAULT_USER_AGENT,
        verify_ssl: bool  = True,
        proxy:      Optional[str] = None,
    ):
        self.timeout    = timeout
        self.delay      = delay
        self.verify_ssl = verify_ssl
        self._last_req  = 0.0
        self._req_count = 0

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent":      user_agent,
            "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection":      "keep-alive",
        })

        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        self.session.max_redirects = 5

    # ─── Rate Limiting ──────────────────────────────────────────────────────────
    def _rate_limit(self):
        now     = time.time()
        elapsed = now - self._last_req
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_req  = time.time()
        self._req_count += 1

    # ─── Core GET ──────────────────────────────────────────────────────────────
    def get(
        self,
        url:     str,
        params:  Optional[Dict] = None,
        headers: Optional[Dict] = None,
        follow_redirects: bool  = True,
    ) -> HttpResponse:
        self._rate_limit()
        try:
            resp = self.session.get(
                url,
                params  = params,
                headers = headers,
                timeout = self.timeout,
                verify  = self.verify_ssl,
                allow_redirects = follow_redirects,
            )
            chain = [r.url for r in resp.history]
            return HttpResponse(
                url          = resp.url,
                status_code  = resp.status_code,
                headers      = dict(resp.headers),
                text         = resp.text,
                elapsed_ms   = resp.elapsed.total_seconds() * 1000,
                redirect_chain = chain,
            )
        except requests.exceptions.SSLError as e:
            return HttpResponse(url=url, status_code=0, headers={}, text="",
                                elapsed_ms=0, error=f"SSL Error: {e}")
        except requests.exceptions.ConnectionError as e:
            return HttpResponse(url=url, status_code=0, headers={}, text="",
                                elapsed_ms=0, error=f"Connection Error: {e}")
        except requests.exceptions.Timeout:
            return HttpResponse(url=url, status_code=0, headers={}, text="",
                                elapsed_ms=self.timeout * 1000, error="Timeout")
        except Exception as e:
            return HttpResponse(url=url, status_code=0, headers={}, text="",
                                elapsed_ms=0, error=str(e))

    # ─── Core POST (safe — for form analysis only) ─────────────────────────────
    def post(
        self,
        url:     str,
        data:    Optional[Dict] = None,
        json:    Optional[Dict] = None,
        headers: Optional[Dict] = None,
    ) -> HttpResponse:
        self._rate_limit()
        try:
            resp = self.session.post(
                url,
                data    = data,
                json    = json,
                headers = headers,
                timeout = self.timeout,
                verify  = self.verify_ssl,
                allow_redirects = True,
            )
            return HttpResponse(
                url         = resp.url,
                status_code = resp.status_code,
                headers     = dict(resp.headers),
                text        = resp.text,
                elapsed_ms  = resp.elapsed.total_seconds() * 1000,
            )
        except Exception as e:
            return HttpResponse(url=url, status_code=0, headers={}, text="",
                                elapsed_ms=0, error=str(e))

    # ─── HEAD request ──────────────────────────────────────────────────────────
    def head(self, url: str) -> HttpResponse:
        self._rate_limit()
        try:
            resp = self.session.head(
                url, timeout=self.timeout, verify=self.verify_ssl, allow_redirects=True
            )
            return HttpResponse(
                url         = resp.url,
                status_code = resp.status_code,
                headers     = dict(resp.headers),
                text        = "",
                elapsed_ms  = resp.elapsed.total_seconds() * 1000,
            )
        except Exception as e:
            return HttpResponse(url=url, status_code=0, headers={}, text="",
                                elapsed_ms=0, error=str(e))

    # ─── Helpers ───────────────────────────────────────────────────────────────
    def get_with_timing(self, url: str, params: Dict = None, n: int = 3) -> float:
        """
        Return average response time in ms over n requests.
        Used for timing anomaly detection.
        """
        times = []
        for _ in range(n):
            r = self.get(url, params=params)
            if r.ok:
                times.append(r.elapsed_ms)
        return sum(times) / len(times) if times else 0.0

    @property
    def request_count(self) -> int:
        return self._req_count
