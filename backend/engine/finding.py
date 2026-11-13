"""Finding dataclass used by all detection modules (in-memory, pre-DB)."""
from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


SEVERITY_CVSS_MAP = {
    Severity.CRITICAL: (9.0, 10.0),
    Severity.HIGH:     (7.0, 8.9),
    Severity.MEDIUM:   (4.0, 6.9),
    Severity.LOW:      (0.1, 3.9),
    Severity.INFO:     (0.0, 0.0),
}


@dataclass
class Finding:
    """Structured finding returned by each detection module."""
    title: str
    vector: str               # module name e.g. "bola", "sqli"
    severity: Severity
    description: str
    business_impact: str
    remediation: str

    # Endpoint info
    endpoint_method: str = ""
    endpoint_path: str = ""

    # Evidence
    evidence_request: str = ""
    evidence_response: str = ""

    # Scoring
    cvss_score: float = 0.0
    cvss_vector: str = ""

    # OWASP / CWE
    owasp_id: str = ""        # e.g. "API1:2023"
    cwe_id: str = ""          # e.g. "CWE-284"
    references: list[str] = field(default_factory=list)

    # Unique ID (generated)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self):
        if self.cvss_score == 0.0 and self.severity != Severity.INFO:
            # Assign midpoint CVSS score based on severity
            lo, hi = SEVERITY_CVSS_MAP[self.severity]
            self.cvss_score = round((lo + hi) / 2, 1)
