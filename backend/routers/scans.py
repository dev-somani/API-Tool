"""
Scans router — create, manage, and stream progress of scans.
Includes WebSocket endpoint for real-time progress updates.
"""
from __future__ import annotations
import asyncio
import json
from typing import Optional, Any
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends, WebSocket, WebSocketDisconnect, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from database import get_db, AsyncSessionLocal
from models.scan import Scan, ScanStatus, ScanMode, Target, ConsentRecord, Endpoint as EndpointModel, Finding
from modules import get_module_info
from ingestion.openapi_parser import parse_openapi
from ingestion.postman_parser import parse_postman
from ingestion.manual_parser import parse_manual

router = APIRouter()

# Active WebSocket connections per scan
_ws_connections: dict[str, list[WebSocket]] = {}


async def _broadcast(scan_id: str, data: dict):
    for ws in _ws_connections.get(scan_id, []):
        try:
            await ws.send_json(data)
        except Exception:
            pass


class ScanCreate(BaseModel):
    target_id: str
    consent_id: str
    name: str
    mode: str = "safe"
    spec_type: Optional[str] = None    # "openapi" | "postman" | "manual"
    spec_content: Optional[str] = None  # raw spec string
    manual_endpoints: Optional[list[dict]] = None
    auth_configs: list[dict] = []
    enabled_modules: list[str] = []
    rate_limit_rps: float = 2.0
    concurrency: int = 5
    timeout: float = 30.0


class ScanOut(BaseModel):
    id: str
    target_id: str
    consent_id: str
    name: str
    status: str
    mode: str
    spec_type: Optional[str]
    total_endpoints: int
    tested_endpoints: int
    progress_pct: float
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error_message: Optional[str]

    class Config:
        from_attributes = True


class FindingOut(BaseModel):
    id: str
    title: str
    severity: str
    cvss_score: float
    cvss_vector: Optional[str]
    owasp_id: Optional[str]
    cwe_id: Optional[str]
    endpoint_method: Optional[str]
    endpoint_path: Optional[str]
    description: str
    business_impact: str
    remediation: str
    evidence_request: Optional[str]
    evidence_response: Optional[str]
    vector: str
    references: list
    is_false_positive: bool

    class Config:
        from_attributes = True


@router.get("/modules")
async def list_modules():
    """List all available detection modules."""
    return get_module_info()


@router.get("/", response_model=list[ScanOut])
async def list_scans(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).order_by(Scan.created_at.desc()))
    return result.scalars().all()


@router.post("/", response_model=ScanOut, status_code=201)
async def create_scan(
    data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Create and immediately launch a scan (runs in background)."""
    # Verify target
    target = await db.get(Target, data.target_id)
    if not target:
        raise HTTPException(404, "Target not found")

    # Verify consent — MANDATORY GATE
    consent = await db.get(ConsentRecord, data.consent_id)
    if not consent:
        raise HTTPException(
            403,
            "A valid consent record is required before scanning. "
            "Please create a consent record confirming authorization to test this target."
        )
    if consent.target_id != data.target_id:
        raise HTTPException(403, "Consent record does not match the target.")

    mode = ScanMode.FULL if data.mode == "full" else ScanMode.SAFE

    # Build spec content
    spec_content = data.spec_content
    if data.spec_type == "manual" and data.manual_endpoints:
        spec_content = json.dumps(data.manual_endpoints)

    scan = Scan(
        target_id=data.target_id,
        consent_id=data.consent_id,
        name=data.name,
        mode=mode,
        spec_type=data.spec_type,
        spec_content=spec_content,
        auth_configs=data.auth_configs,
        enabled_modules=data.enabled_modules,
        rate_limit_rps=data.rate_limit_rps,
        concurrency=data.concurrency,
        timeout=data.timeout,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    scan_id = scan.id
    asyncio.create_task(_run_scan_background(scan_id))
    return scan


async def _run_scan_background(scan_id: str):
    """Background task to execute the scan engine."""
    from engine.test_engine import TestEngine

    async with AsyncSessionLocal() as db:
        # Load scan with relationships
        result = await db.execute(
            select(Scan)
            .options(selectinload(Scan.target), selectinload(Scan.consent))
            .where(Scan.id == scan_id)
        )
        scan = result.scalar_one_or_none()
        if not scan:
            return

        try:
            # Parse endpoints from spec
            endpoints = await _parse_endpoints(scan)
            scan.total_endpoints = len(endpoints)
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.utcnow()
            await db.commit()

            # Persist endpoint inventory
            for ep in endpoints:
                ep_model = EndpointModel(
                    scan_id=scan.id,
                    method=ep.method,
                    path=ep.path,
                    full_url=ep.full_url,
                    parameters=ep.parameters,
                    request_body_schema=ep.request_body_schema,
                    response_schemas=ep.response_schemas,
                    tags=ep.tags,
                    summary=ep.summary,
                    requires_auth=ep.requires_auth,
                )
                db.add(ep_model)
            await db.commit()

            await _broadcast(scan_id, {"type": "endpoints_discovered", "count": len(endpoints)})

            # Run engine
            engine = TestEngine(scan, db)
            await engine.run(endpoints)
            await db.commit()

            await _broadcast(scan_id, {"type": "scan_completed", "scan_id": scan_id})

        except Exception as e:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            await db.commit()
            await _broadcast(scan_id, {"type": "scan_failed", "error": str(e)})


async def _detect_api_prefix(base_url: str, spec_content: str, spec_type: str) -> str:
    """If base_url points to a frontend SPA root, probe for common backend prefixes like /api/v1 or /api."""
    import httpx
    clean_base = base_url.rstrip("/")
    # Sample path to probe
    sample_paths = ["/health", "/auth/login", "/users", "/api/health"]
    if spec_content and spec_type == "postman":
        try:
            coll_data = json.loads(spec_content)
            for item in coll_data.get("item", []):
                req = item.get("request", {})
                url_data = req.get("url", {})
                if isinstance(url_data, dict):
                    parts = url_data.get("path", [])
                    if parts:
                        sample_paths.insert(0, "/" + "/".join(str(p) for p in parts))
        except Exception:
            pass

    async with httpx.AsyncClient(verify=False, timeout=5) as client:
        test_path = sample_paths[0] if sample_paths else "/health"
        for prefix in ["", "/api/v1", "/api", "/v1"]:
            candidate = f"{clean_base}{prefix}"
            try:
                r = await client.get(f"{candidate}{test_path}")
                ct = r.headers.get("content-type", "").lower()
                text = r.text.lower()
                if "text/html" not in ct and "route not found" not in text and r.status_code in (200, 401, 403, 400, 204):
                    return candidate
            except Exception:
                pass
    return clean_base


async def _parse_endpoints(scan: Scan):
    """Parse endpoints from spec content with automatic API prefix resolution."""
    from modules.base import Endpoint
    base_url = await _detect_api_prefix(scan.target.base_url, scan.spec_content or "", scan.spec_type or "")

    if scan.spec_type == "openapi" and scan.spec_content:
        return parse_openapi(scan.spec_content, base_url)
    elif scan.spec_type == "postman" and scan.spec_content:
        return parse_postman(scan.spec_content, base_url)
    elif scan.spec_type == "manual" and scan.spec_content:
        try:
            entries = json.loads(scan.spec_content)
        except Exception:
            entries = []
        return parse_manual(entries, base_url)
    else:
        # Single target — test just the base URL
        return [Endpoint(method="GET", path="/", full_url=base_url)]


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@router.delete("/{scan_id}", status_code=200)
async def delete_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
        raise HTTPException(400, "Running scans must be cancelled before deletion")

    await db.delete(scan)
    await db.commit()
    return {"message": "Scan deleted", "id": scan_id}


@router.delete("/{scan_id}/cancel", status_code=200)
async def cancel_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    from engine.test_engine import cancel_scan as _cancel
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status != ScanStatus.RUNNING:
        raise HTTPException(400, "Scan is not running")
    _cancel(scan_id)
    return {"message": "Cancellation requested"}


@router.get("/{scan_id}/findings", response_model=list[FindingOut])
async def list_findings(
    scan_id: str,
    severity: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(Finding).where(
        Finding.scan_id == scan_id,
        Finding.is_false_positive == False,
        Finding.evidence_request.is_not(None),
        Finding.evidence_response.is_not(None),
    )
    if severity:
        from models.scan import Severity as DBSeverity
        query = query.where(Finding.severity == DBSeverity(severity))
    result = await db.execute(query.order_by(Finding.cvss_score.desc()))
    return result.scalars().all()


@router.patch("/{scan_id}/findings/{finding_id}/false-positive", status_code=200)
async def toggle_false_positive(
    scan_id: str, finding_id: str, db: AsyncSession = Depends(get_db)
):
    finding = await db.get(Finding, finding_id)
    if not finding or finding.scan_id != scan_id:
        raise HTTPException(404, "Finding not found")
    finding.is_false_positive = not finding.is_false_positive
    await db.flush()
    return {"id": finding.id, "is_false_positive": finding.is_false_positive}


@router.get("/{scan_id}/audit-log")
async def get_audit_log(
    scan_id: str,
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    from models.scan import AuditLog
    result = await db.execute(
        select(AuditLog)
        .where(AuditLog.scan_id == scan_id)
        .order_by(AuditLog.timestamp)
        .limit(limit)
        .offset(offset)
    )
    logs = result.scalars().all()
    return [
        {
            "id": l.id,
            "module_name": l.module_name,
            "request_method": l.request_method,
            "request_url": l.request_url,
            "response_status": l.response_status,
            "response_time_ms": l.response_time_ms,
            "is_finding": l.is_finding,
            "timestamp": l.timestamp.isoformat(),
        }
        for l in logs
    ]


@router.websocket("/{scan_id}/ws")
async def scan_websocket(scan_id: str, websocket: WebSocket):
    """WebSocket for real-time scan progress."""
    await websocket.accept()
    if scan_id not in _ws_connections:
        _ws_connections[scan_id] = []
    _ws_connections[scan_id].append(websocket)

    try:
        while True:
            # Keep alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        _ws_connections[scan_id].remove(websocket)
