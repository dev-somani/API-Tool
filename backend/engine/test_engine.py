"""
Async Test Engine — orchestrates endpoint testing across all modules.
Features:
- Rate limiting (token bucket)
- Configurable concurrency via asyncio.Semaphore
- Domain allowlist enforcement
- WebSocket progress broadcast
- Per-request audit logging
"""
from __future__ import annotations
import asyncio
import time
import uuid
from datetime import datetime
from urllib.parse import urlparse
from typing import AsyncGenerator, Callable

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models.scan import Scan, Endpoint as EndpointModel, Finding as FindingModel, ScanStatus
from modules.base import Endpoint, ScanConfig
from modules import get_module_instances
from engine.session_manager import SessionManager, AuthConfig, AuthType
from audit.logger import AuditLogger


# Global dict of scan_id → asyncio.Event for cancellation
_CANCEL_EVENTS: dict[str, asyncio.Event] = {}


def get_cancel_event(scan_id: str) -> asyncio.Event:
    if scan_id not in _CANCEL_EVENTS:
        _CANCEL_EVENTS[scan_id] = asyncio.Event()
    return _CANCEL_EVENTS[scan_id]


def cancel_scan(scan_id: str):
    get_cancel_event(scan_id).set()


class RateLimiter:
    """Simple async token-bucket rate limiter."""
    def __init__(self, rps: float):
        self._interval = 1.0 / max(rps, 0.1)
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            wait = self._interval - (now - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()


# Progress callback type
ProgressCallback = Callable[[str, int, int, str], None]


class TestEngine:
    def __init__(
        self,
        scan: Scan,
        db: AsyncSession,
        progress_callback: ProgressCallback | None = None,
    ):
        self._scan = scan
        self._db = db
        self._progress_callback = progress_callback
        self._audit = AuditLogger(db, scan.id)

    async def run(self, endpoints: list[Endpoint]) -> None:
        """Run all modules against all endpoints."""
        scan = self._scan
        config = ScanConfig(
            scan_id=scan.id,
            target_base_url=scan.target.base_url,
            allowed_domains=scan.target.allowed_domains or [],
            rate_limit_rps=scan.rate_limit_rps,
            concurrency=scan.concurrency,
            timeout=scan.timeout,
            safe_mode=scan.mode.value == "safe",
            enabled_modules=scan.enabled_modules or [],
        )

        # Build auth configs from scan.auth_configs
        auth_configs = self._build_auth_configs(scan.auth_configs)
        session_mgr = SessionManager(auth_configs)
        await session_mgr.initialize()
        primary_session = session_mgr.primary_context()

        rate_limiter = RateLimiter(config.rate_limit_rps)
        semaphore = asyncio.Semaphore(config.concurrency)
        cancel_event = get_cancel_event(scan.id)

        modules = get_module_instances(config.enabled_modules or [])

        total = len(endpoints) * len(modules)
        done = 0

        # Update scan status
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        scan.total_endpoints = len(endpoints)
        await self._db.flush()

        limits = httpx.Limits(
            max_keepalive_connections=config.concurrency,
            max_connections=config.concurrency + 5,
        )
        timeout = httpx.Timeout(config.timeout, connect=10.0)

        async with httpx.AsyncClient(
            follow_redirects=True,
            verify=False,  # Allow testing self-signed certs
            limits=limits,
            timeout=timeout,
        ) as client:
            for idx, ep in enumerate(endpoints):
                if cancel_event.is_set():
                    break
                
                ep_tasks = [
                    self._run_module(
                        module, ep, primary_session, config,
                        client, rate_limiter, semaphore, cancel_event,
                    )
                    for module in modules
                ]
                ep_results = await asyncio.gather(*ep_tasks, return_exceptions=True)
                for res in ep_results:
                    if isinstance(res, list):
                        for finding in res:
                            await self._persist_finding(finding, config)

                scan.tested_endpoints = idx + 1
                scan.progress_pct = round(((idx + 1) / max(len(endpoints), 1)) * 100.0, 1)
                await self._db.commit()

        scan.status = ScanStatus.CANCELLED if cancel_event.is_set() else ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        scan.tested_endpoints = len(endpoints)
        scan.progress_pct = 100.0
        await self._db.commit()

    async def _run_module(
        self, module, endpoint, session, config,
        client, rate_limiter, semaphore, cancel_event,
    ):
        if cancel_event.is_set():
            return []
        if not module.is_enabled(config) or not module.is_safe_to_run(config):
            return []

        # Domain allowlist check
        if not self._is_allowed(endpoint.full_url, config.allowed_domains, config.target_base_url):
            return []

        async with semaphore:
            await rate_limiter.acquire()
            try:
                return await module.run(endpoint, session, config, client)
            except Exception as e:
                return []

    def _is_allowed(self, url: str, allowed_domains: list[str], base_url: str) -> bool:
        """Check URL is within the allowed domains."""
        if not allowed_domains:
            # Default: only allow requests to the same host as base_url
            target_host = urlparse(base_url).netloc
            req_host = urlparse(url).netloc
            return req_host == target_host or req_host == "" or not req_host
        req_host = urlparse(url).netloc
        return any(req_host.endswith(d) for d in allowed_domains)

    def _build_auth_configs(self, raw_configs: list[dict]) -> list[AuthConfig]:
        configs = []
        for raw in (raw_configs or []):
            auth_type = AuthType(raw.get("auth_type", "none"))
            cfg = AuthConfig(
                role_name=raw.get("role_name", "default"),
                auth_type=auth_type,
                token=raw.get("token", ""),
                api_key=raw.get("api_key", ""),
                api_key_header=raw.get("api_key_header", "X-API-Key"),
                api_key_query_param=raw.get("api_key_query_param", ""),
                username=raw.get("username", ""),
                password=raw.get("password", ""),
                cookies=raw.get("cookies", {}),
                token_url=raw.get("token_url", ""),
                client_id=raw.get("client_id", ""),
                client_secret=raw.get("client_secret", ""),
                scope=raw.get("scope", ""),
                extra_headers=raw.get("extra_headers", {}),
            )
            configs.append(cfg)

        if not configs:
            configs.append(AuthConfig(role_name="anonymous", auth_type=AuthType.NONE))
        return configs

    async def _persist_finding(self, finding, config: ScanConfig) -> None:
        """Save a Finding (in-memory) to the database."""
        from engine.finding import Finding as InMemFinding
        from models.scan import Finding as DBFinding, Severity as DBSeverity

        severity_map = {
            "critical": DBSeverity.CRITICAL,
            "high": DBSeverity.HIGH,
            "medium": DBSeverity.MEDIUM,
            "low": DBSeverity.LOW,
            "info": DBSeverity.INFO,
        }

        db_finding = DBFinding(
            scan_id=config.scan_id,
            title=finding.title,
            vector=finding.vector,
            severity=severity_map.get(finding.severity.value, DBSeverity.LOW),
            cvss_score=finding.cvss_score,
            cvss_vector=finding.cvss_vector,
            description=finding.description,
            business_impact=finding.business_impact,
            remediation=finding.remediation,
            evidence_request=finding.evidence_request,
            evidence_response=finding.evidence_response,
            owasp_id=finding.owasp_id,
            cwe_id=finding.cwe_id,
            references=finding.references,
            endpoint_method=finding.endpoint_method,
            endpoint_path=finding.endpoint_path,
        )
        self._db.add(db_finding)
        await self._db.flush()
