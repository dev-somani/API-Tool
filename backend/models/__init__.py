"""Models package — imports all ORM models so SQLAlchemy registers them."""
from models.scan import (  # noqa: F401
    Target, ConsentRecord, Scan, Endpoint, Finding, AuditLog, ScanStatus,
    Severity, ScanMode
)
from models.user import User  # noqa: F401
