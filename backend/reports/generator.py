"""
Report Generator — produces JSON, HTML, and PDF reports.
"""
from __future__ import annotations
import json
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from config import settings
from models.scan import Scan, Finding, Endpoint as EndpointModel, Severity

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

OWASP_CATEGORIES = [
    ("API1:2023", "Broken Object Level Authorization"),
    ("API2:2023", "Broken Authentication"),
    ("API3:2023", "Broken Object Property Level Authorization"),
    ("API4:2023", "Unrestricted Resource Consumption"),
    ("API5:2023", "Broken Function Level Authorization"),
    ("API6:2023", "Unrestricted Access to Sensitive Business Flows"),
    ("API7:2023", "Server-Side Request Forgery"),
    ("API8:2023", "Security Misconfiguration"),
    ("API9:2023", "Improper Inventory Management"),
    ("API10:2023", "Unsafe Consumption of APIs"),
]


def _severity_order(s: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(s.lower(), 5)


def _overall_risk(findings: list) -> str:
    if any(f.severity.value == "critical" for f in findings):
        return "CRITICAL"
    if any(f.severity.value == "high" for f in findings):
        return "HIGH"
    if any(f.severity.value == "medium" for f in findings):
        return "MEDIUM"
    if any(f.severity.value == "low" for f in findings):
        return "LOW"
    return "INFO"


def _is_confirmed_finding(finding: Finding) -> bool:
    """Only expose findings backed by a reproducible request and response."""
    title = (finding.title or "").lower()
    return (
        bool(finding.evidence_request and finding.evidence_response)
        and "manual verification" not in title
    )


def _build_context(scan: Scan, findings: list, endpoints: list) -> dict:
    findings_sorted = sorted(findings, key=lambda f: _severity_order(f.severity.value))

    counts = {s: 0 for s in ["critical", "high", "medium", "low", "info"]}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    # OWASP coverage matrix
    owasp_matrix = []
    tested_categories = {f.owasp_id for f in findings if f.owasp_id}
    for owasp_id, title in OWASP_CATEGORIES:
        category_findings = [f for f in findings if f.owasp_id == owasp_id]
        status = "FAIL" if category_findings else ("PASS" if owasp_id in tested_categories else "NOT TESTED")
        owasp_matrix.append({
            "id": owasp_id,
            "title": title,
            "status": status,
            "findings_count": len(category_findings),
        })

    return {
        "scan": scan,
        "findings": findings_sorted,
        "endpoints": endpoints,
        "counts": counts,
        "total_findings": len(findings),
        "overall_risk": _overall_risk(findings),
        "owasp_matrix": owasp_matrix,
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "consent": scan.consent,
    }


async def generate_json_report(scan: Scan, db: AsyncSession) -> dict:
    """Generate a JSON-serializable report dict."""
    findings = (await db.execute(
        select(Finding).where(Finding.scan_id == scan.id).where(Finding.is_false_positive == False)
    )).scalars().all()
    findings = [finding for finding in findings if _is_confirmed_finding(finding)]

    endpoints = (await db.execute(
        select(EndpointModel).where(EndpointModel.scan_id == scan.id)
    )).scalars().all()

    ctx = _build_context(scan, list(findings), list(endpoints))

    return {
        "report_version": "1.0",
        "generated_at": ctx["generated_at"],
        "scan": {
            "id": scan.id,
            "name": scan.name,
            "status": scan.status.value,
            "mode": scan.mode.value,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "target": {
                "name": scan.target.name,
                "base_url": scan.target.base_url,
            },
            "consent": {
                "tester_name": scan.consent.tester_name,
                "tester_email": scan.consent.tester_email,
                "scope": scan.consent.scope_description,
                "consented_at": scan.consent.consented_at.isoformat(),
            } if scan.consent else None,
        },
        "summary": {
            "total_findings": ctx["total_findings"],
            "overall_risk": ctx["overall_risk"],
            "by_severity": ctx["counts"],
            "endpoints_tested": len(endpoints),
        },
        "owasp_coverage": ctx["owasp_matrix"],
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
                "owasp_id": f.owasp_id,
                "cwe_id": f.cwe_id,
                "endpoint_method": f.endpoint_method,
                "endpoint_path": f.endpoint_path,
                "description": f.description,
                "business_impact": f.business_impact,
                "remediation": f.remediation,
                "evidence_request": f.evidence_request,
                "evidence_response": f.evidence_response,
                "references": f.references,
                "vector": f.vector,
            }
            for f in ctx["findings"]
        ],
        "endpoints": [
            {
                "method": e.method,
                "path": e.path,
                "full_url": e.full_url,
                "summary": e.summary,
                "requires_auth": e.requires_auth,
            }
            for e in endpoints
        ],
    }


async def generate_html_report(scan: Scan, db: AsyncSession) -> str:
    """Generate an HTML report string."""
    findings = (await db.execute(
        select(Finding).where(Finding.scan_id == scan.id).where(Finding.is_false_positive == False)
    )).scalars().all()
    findings = [finding for finding in findings if _is_confirmed_finding(finding)]
    endpoints = (await db.execute(
        select(EndpointModel).where(EndpointModel.scan_id == scan.id)
    )).scalars().all()

    ctx = _build_context(scan, list(findings), list(endpoints))

    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "j2"]),
    )
    template = env.get_template("report.html.j2")
    return template.render(**ctx)


async def generate_pdf_report(scan: Scan, db: AsyncSession) -> bytes:
    """Generate a PDF report using WeasyPrint."""
    html = await generate_html_report(scan, db)
    try:
        from weasyprint import HTML as WeasyHTML
        return WeasyHTML(string=html).write_pdf()
    except ImportError:
        raise RuntimeError("WeasyPrint is not installed. Run: pip install weasyprint")
