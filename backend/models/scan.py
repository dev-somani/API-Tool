"""
Core ORM models: Target, ConsentRecord, Scan, Endpoint, Finding, AuditLog.
"""
import uuid
import enum
from datetime import datetime

from sqlalchemy import (
    String, Text, Integer, Float, Boolean, DateTime, Enum as SAEnum,
    ForeignKey, JSON
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.utcnow()


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────

class ScanStatus(str, enum.Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    CANCELLED = "cancelled"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class ScanMode(str, enum.Enum):
    SAFE = "safe"   # Read-only checks only
    FULL = "full"   # Includes state-changing / destructive payloads


# ─────────────────────────────────────────────────────────────────────────────
# Target
# ─────────────────────────────────────────────────────────────────────────────

class Target(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # JSON list of allowed domains/IPs (allowlist guardrail)
    allowed_domains: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)

    scans: Mapped[list["Scan"]] = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
    consents: Mapped[list["ConsentRecord"]] = relationship("ConsentRecord", back_populates="target")


# ─────────────────────────────────────────────────────────────────────────────
# ConsentRecord — mandatory authorization gate
# ─────────────────────────────────────────────────────────────────────────────

class ConsentRecord(Base):
    __tablename__ = "consent_records"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(String, ForeignKey("targets.id"), nullable=False)
    tester_name: Mapped[str] = mapped_column(String(256), nullable=False)
    tester_email: Mapped[str] = mapped_column(String(256), nullable=False)
    authorization_statement: Mapped[str] = mapped_column(Text, nullable=False)
    scope_description: Mapped[str] = mapped_column(Text, nullable=False)
    consented_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    
    target: Mapped["Target"] = relationship("Target", back_populates="consents")
    scans: Mapped[list["Scan"]] = relationship("Scan", back_populates="consent")


# ─────────────────────────────────────────────────────────────────────────────
# Scan
# ─────────────────────────────────────────────────────────────────────────────

class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(String, ForeignKey("targets.id"), nullable=False)
    consent_id: Mapped[str] = mapped_column(String, ForeignKey("consent_records.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(SAEnum(ScanStatus), default=ScanStatus.PENDING)
    mode: Mapped[ScanMode] = mapped_column(SAEnum(ScanMode), default=ScanMode.SAFE)

    # Spec source: "openapi" | "postman" | "manual"
    spec_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    spec_content: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Auth configs as JSON list of AuthConfig dicts
    auth_configs: Mapped[list] = mapped_column(JSON, default=list)

    # Which modules to run (empty = all)
    enabled_modules: Mapped[list] = mapped_column(JSON, default=list)

    # Scan configuration
    rate_limit_rps: Mapped[float] = mapped_column(Float, default=2.0)
    concurrency: Mapped[int] = mapped_column(Integer, default=5)
    timeout: Mapped[float] = mapped_column(Float, default=30.0)

    # Progress tracking
    total_endpoints: Mapped[int] = mapped_column(Integer, default=0)
    tested_endpoints: Mapped[int] = mapped_column(Integer, default=0)
    progress_pct: Mapped[float] = mapped_column(Float, default=0.0)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Error message if status == failed
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    target: Mapped["Target"] = relationship("Target", back_populates="scans")
    consent: Mapped["ConsentRecord"] = relationship("ConsentRecord", back_populates="scans")
    endpoints: Mapped[list["Endpoint"]] = relationship("Endpoint", back_populates="scan", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    audit_logs: Mapped[list["AuditLog"]] = relationship("AuditLog", back_populates="scan", cascade="all, delete-orphan")


# ─────────────────────────────────────────────────────────────────────────────
# Endpoint — discovered/parsed endpoints in a scan
# ─────────────────────────────────────────────────────────────────────────────

class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    method: Mapped[str] = mapped_column(String(16), nullable=False)
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    full_url: Mapped[str] = mapped_column(String(4096), nullable=False)

    # Parsed schema info
    parameters: Mapped[list] = mapped_column(JSON, default=list)
    request_body_schema: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    response_schemas: Mapped[dict] = mapped_column(JSON, default=dict)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    summary: Mapped[str | None] = mapped_column(String(512), nullable=True)
    requires_auth: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="endpoints")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="endpoint")


# ─────────────────────────────────────────────────────────────────────────────
# Finding
# ─────────────────────────────────────────────────────────────────────────────

class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    endpoint_id: Mapped[str | None] = mapped_column(String, ForeignKey("endpoints.id"), nullable=True)

    # Classification
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    vector: Mapped[str] = mapped_column(String(64), nullable=False)   # module name
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity), nullable=False)
    cvss_score: Mapped[float] = mapped_column(Float, default=0.0)
    cvss_vector: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Details
    description: Mapped[str] = mapped_column(Text, nullable=False)
    business_impact: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)

    # Evidence (sanitized req/resp)
    evidence_request: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_response: Mapped[str | None] = mapped_column(Text, nullable=True)

    # OWASP / CWE references
    owasp_id: Mapped[str | None] = mapped_column(String(32), nullable=True)   # e.g. "API1:2023"
    cwe_id: Mapped[str | None] = mapped_column(String(32), nullable=True)     # e.g. "CWE-284"
    references: Mapped[list] = mapped_column(JSON, default=list)

    # Endpoint info (denormalized for easy reporting)
    endpoint_method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    endpoint_path: Mapped[str | None] = mapped_column(String(2048), nullable=True)

    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
    endpoint: Mapped["Endpoint | None"] = relationship("Endpoint", back_populates="findings")


# ─────────────────────────────────────────────────────────────────────────────
# AuditLog — immutable log of every HTTP request sent during a scan
# ─────────────────────────────────────────────────────────────────────────────

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    module_name: Mapped[str] = mapped_column(String(64), nullable=False)

    # Request details
    request_method: Mapped[str] = mapped_column(String(16), nullable=False)
    request_url: Mapped[str] = mapped_column(String(4096), nullable=False)
    request_headers: Mapped[dict] = mapped_column(JSON, default=dict)
    request_body: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Response details
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_headers: Mapped[dict] = mapped_column(JSON, default=dict)
    response_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_time_ms: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Meta
    is_finding: Mapped[bool] = mapped_column(Boolean, default=False)
    finding_id: Mapped[str | None] = mapped_column(String, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=_now)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="audit_logs")
