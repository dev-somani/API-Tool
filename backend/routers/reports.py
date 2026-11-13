"""
Reports router — download HTML, PDF, and JSON reports.
"""
from __future__ import annotations
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from database import get_db
from models.scan import Scan, ScanStatus
from reports.generator import generate_json_report, generate_html_report, generate_pdf_report

router = APIRouter()


async def _load_scan(scan_id: str, db: AsyncSession) -> Scan:
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.target), selectinload(Scan.consent))
        .where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status not in (ScanStatus.COMPLETED, ScanStatus.CANCELLED):
        raise HTTPException(
            400,
            f"Report not available — scan status is '{scan.status.value}'. "
            "Reports are generated after scan completion."
        )
    return scan


@router.get("/{scan_id}/json")
async def download_json_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await _load_scan(scan_id, db)
    report = await generate_json_report(scan, db)
    filename = f"vapt-report-{scan.name.replace(' ', '-')}-{scan_id[:8]}.json"
    return JSONResponse(
        content=report,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/html", response_class=HTMLResponse)
async def download_html_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await _load_scan(scan_id, db)
    html = await generate_html_report(scan, db)
    filename = f"vapt-report-{scan.name.replace(' ', '-')}-{scan_id[:8]}.html"
    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/pdf")
async def download_pdf_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await _load_scan(scan_id, db)
    try:
        pdf_bytes = await generate_pdf_report(scan, db)
    except RuntimeError as e:
        raise HTTPException(501, str(e))

    filename = f"vapt-report-{scan.name.replace(' ', '-')}-{scan_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
