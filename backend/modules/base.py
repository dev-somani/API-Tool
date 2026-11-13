"""
Abstract base class for all detection modules.

Every module must implement:
    async def run(endpoint, session, config, client) -> list[Finding]
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import httpx

from engine.finding import Finding, Severity
from engine.session_manager import SessionContext


@dataclass
class Endpoint:
    """Resolved endpoint ready for testing."""
    method: str
    path: str
    full_url: str
    parameters: list[dict] = field(default_factory=list)
    request_body_schema: dict | None = None
    response_schemas: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    summary: str = ""
    requires_auth: bool = True
    endpoint_id: str = ""


@dataclass
class ScanConfig:
    """Scan-level configuration passed to every module."""
    scan_id: str
    target_base_url: str
    allowed_domains: list[str]
    rate_limit_rps: float = 2.0
    concurrency: int = 5
    timeout: float = 30.0
    safe_mode: bool = True
    enabled_modules: list[str] = field(default_factory=list)  # empty = all


class BaseModule(ABC):
    """Abstract detection module interface."""

    #: Unique slug used in module registry and Finding.vector
    name: str = ""
    #: Human-readable title
    title: str = ""
    #: OWASP category e.g. "API1:2023"
    owasp_category: str = ""
    #: CWE ID(s) e.g. ["CWE-284"]
    cwe_ids: list[str] = []
    #: Default severity when a finding is raised
    severity_default: Severity = Severity.MEDIUM
    #: If True, module performs read-only checks and runs in safe mode
    safe_mode_compatible: bool = True
    #: If True, module may mutate state; requires full-mode
    destructive: bool = False

    @abstractmethod
    async def run(
        self,
        endpoint: Endpoint,
        session: SessionContext,
        config: ScanConfig,
        client: httpx.AsyncClient,
    ) -> list[Finding]:
        """Execute all checks for this module against `endpoint`."""
        ...

    @staticmethod
    def is_html_or_spa_response(resp: httpx.Response) -> bool:
        """Check if the response is an HTML page (SPA frontend fallback) rather than an API response."""
        ct = resp.headers.get("content-type", "").lower()
        if "text/html" in ct:
            return True
        text_head = resp.text[:300].strip().lower()
        if text_head.startswith("<!doctype html") or text_head.startswith("<html") or "<head" in text_head:
            return True
        return False

    @staticmethod
    def is_unmapped_api_response(resp: httpx.Response) -> bool:
        """Check if the API route is not implemented or 404."""
        if resp.status_code in (404, 405, 501, 502, 503):
            return True
        text = resp.text.lower()
        if "route not found" in text or "cannot get" in text or "cannot post" in text:
            return True
        return False

    @staticmethod
    def format_evidence_response(resp: httpx.Response, highlight_text: str = "", max_len: int = 500) -> str:
        """Format a clear, readable evidence block showing status, content-type, and relevant body."""
        ct = resp.headers.get("content-type", "application/octet-stream")
        body = resp.text.strip()
        
        # If JSON, format cleanly
        try:
            import json
            parsed = json.loads(body)
            body = json.dumps(parsed, indent=2)
        except Exception:
            pass

        if len(body) > max_len:
            if highlight_text and highlight_text in body:
                idx = body.find(highlight_text)
                start = max(0, idx - 100)
                end = min(len(body), idx + len(highlight_text) + 200)
                body = f"... {body[start:end]} ..."
            else:
                body = body[:max_len] + " ... [truncated]"

        headers_str = ""
        for h in ["access-control-allow-origin", "access-control-allow-credentials", "server", "x-powered-by"]:
            if h in resp.headers:
                headers_str += f"{h}: {resp.headers[h]}\n"

        return f"HTTP {resp.status_code} ({ct})\n{headers_str}\n{body}".strip()

    def _build_finding(self, **kwargs) -> Finding:
        """Helper to build a Finding with module defaults pre-filled."""
        return Finding(
            vector=self.name,
            owasp_id=kwargs.pop("owasp_id", self.owasp_category),
            cwe_id=kwargs.pop("cwe_id", self.cwe_ids[0] if self.cwe_ids else ""),
            **kwargs,
        )

    def is_enabled(self, config: ScanConfig) -> bool:
        """Check if this module is enabled for the given scan config."""
        if not config.enabled_modules:
            return True  # all enabled
        return self.name in config.enabled_modules

    def is_safe_to_run(self, config: ScanConfig) -> bool:
        """Check if module can run given safe/full mode config."""
        if config.safe_mode and self.destructive:
            return False
        return True
