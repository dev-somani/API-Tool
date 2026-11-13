"""
Audit Logger — immutable log of every HTTP request sent during a scan.
Writes to the AuditLog table for legal defensibility.
"""
from __future__ import annotations
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

from models.scan import AuditLog


class AuditLogger:
    def __init__(self, session: AsyncSession, scan_id: str):
        self._session = session
        self._scan_id = scan_id

    async def log(
        self,
        module_name: str,
        request_method: str,
        request_url: str,
        request_headers: dict,
        request_body: str | None,
        response_status: int | None,
        response_headers: dict,
        response_body: str | None,
        response_time_ms: float | None,
        is_finding: bool = False,
        finding_id: str | None = None,
    ) -> None:
        """Persist a single request/response pair to the audit log."""
        # Sanitize sensitive headers before logging
        safe_headers = {
            k: ("***REDACTED***" if k.lower() == "authorization" else v)
            for k, v in (request_headers or {}).items()
        }
        entry = AuditLog(
            scan_id=self._scan_id,
            module_name=module_name,
            request_method=request_method,
            request_url=request_url,
            request_headers=safe_headers,
            request_body=request_body[:4096] if request_body else None,
            response_status=response_status,
            response_headers=dict(response_headers or {}),
            response_body=response_body[:4096] if response_body else None,
            response_time_ms=response_time_ms,
            is_finding=is_finding,
            finding_id=finding_id,
            timestamp=datetime.utcnow(),
        )
        self._session.add(entry)
        # Flush periodically to avoid large uncommitted transactions
        try:
            await self._session.flush()
        except Exception:
            pass
