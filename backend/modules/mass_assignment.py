"""
API3:2023 — Broken Object Property Level Authorization
Tests: mass assignment (inject extra fields) + excessive data exposure.
"""
from __future__ import annotations
import json
import httpx

from modules.base import BaseModule, Endpoint, ScanConfig
from engine.finding import Finding, Severity
from engine.session_manager import SessionContext

PRIVILEGE_ESCALATION_FIELDS = [
    "isAdmin", "is_admin", "admin", "role", "roles",
    "permission", "permissions", "privilege", "group",
    "isStaff", "is_staff", "isSuperuser", "is_superuser",
    "verified", "isVerified", "is_verified",
    "credits", "balance", "price",
]

SENSITIVE_RESPONSE_FIELDS = [
    "password", "passwd", "secret", "token", "api_key",
    "ssn", "credit_card", "card_number", "cvv", "pin",
    "private_key", "private", "internal",
]


class MassAssignmentModule(BaseModule):
    name = "mass_assignment"
    title = "Broken Object Property Level Authorization"
    owasp_category = "API3:2023"
    cwe_ids = ["CWE-915", "CWE-200"]
    severity_default = Severity.HIGH
    safe_mode_compatible = True
    destructive = False

    async def run(
        self,
        endpoint: Endpoint,
        session: SessionContext,
        config: ScanConfig,
        client: httpx.AsyncClient,
    ) -> list[Finding]:
        findings: list[Finding] = []
        if not self.is_enabled(config):
            return findings

        # 1. Excessive data exposure — check baseline response
        req_kwargs = session.apply({"headers": {}})
        try:
            resp = await client.request(
                endpoint.method, endpoint.full_url,
                timeout=config.timeout, **req_kwargs
            )
            findings.extend(self._check_excessive_exposure(endpoint, resp))
        except Exception:
            pass

        # 2. Mass assignment — only for POST/PUT/PATCH
        if endpoint.method.upper() in ("POST", "PUT", "PATCH"):
            findings.extend(
                await self._test_mass_assignment(endpoint, session, config, client)
            )

        return findings

    def _check_excessive_exposure(
        self, endpoint: Endpoint, resp: httpx.Response
    ) -> list[Finding]:
        findings = []
        if resp.status_code not in (200, 201):
            return findings
        try:
            body = resp.json()
            body_str = json.dumps(body).lower()
        except Exception:
            return findings

        exposed = [f for f in SENSITIVE_RESPONSE_FIELDS if f in body_str]
        if exposed:
            findings.append(self._build_finding(
                title="Excessive Data Exposure in API Response",
                severity=Severity.HIGH,
                cvss_score=7.5,
                description=(
                    f"The API response contains potentially sensitive fields: {', '.join(exposed)}. "
                    "The API may be returning more data than the client needs."
                ),
                business_impact=(
                    "Sensitive information such as passwords, tokens, or PII is exposed to clients, "
                    "enabling attackers to collect it via interception or JS injection."
                ),
                remediation=(
                    "Apply a response allowlist (use DTOs/serializers) to only expose fields "
                    "required by the client. Never return password hashes, private keys, "
                    "or internal metadata in API responses."
                ),
                endpoint_method=endpoint.method,
                endpoint_path=endpoint.path,
                evidence_response=f"HTTP {resp.status_code}\nSensitive fields found: {exposed}\n{resp.text[:500]}",
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                ],
            ))
        return findings

    async def _test_mass_assignment(
        self, endpoint: Endpoint, session: SessionContext,
        config: ScanConfig, client: httpx.AsyncClient,
    ) -> list[Finding]:
        findings = []
        # Build a payload with privilege-escalation fields
        inject_payload = {f: True for f in PRIVILEGE_ESCALATION_FIELDS[:5]}
        inject_payload.update({"role": "admin", "isAdmin": True, "permissions": ["admin"]})

        req_kwargs = session.apply({"headers": {
            "Content-Type": "application/json",
        }})

        try:
            resp = await client.request(
                endpoint.method, endpoint.full_url,
                content=json.dumps(inject_payload).encode(),
                timeout=config.timeout,
                **req_kwargs,
            )
        except Exception:
            return findings

        # Filter out HTML SPA pages and unmapped responses
        if self.is_html_or_spa_response(resp) or self.is_unmapped_api_response(resp):
            return findings

        # If server accepts the request without error, flag for review
        if resp.status_code in (200, 201, 204):
            try:
                resp_body = resp.json()
                resp_str = json.dumps(resp_body).lower()
            except Exception:
                resp_str = resp.text.lower()

            # Check if any injected field is reflected in the response (confirms acceptance)
            reflected = any(f.lower() in resp_str for f in PRIVILEGE_ESCALATION_FIELDS)
            if reflected:
                findings.append(self._build_finding(
                    title="Potential Mass Assignment Vulnerability",
                    severity=Severity.HIGH,
                    cvss_score=8.0,
                    description=(
                        "The API accepted a request body containing privilege-escalation fields "
                        f"({', '.join(list(inject_payload.keys())[:3])}, ...) and reflected "
                        "them in the response. The server may be binding request fields directly "
                        "to internal objects without an allowlist."
                    ),
                    business_impact=(
                        "An attacker can set arbitrary object properties (e.g., isAdmin, role) "
                        "to escalate privileges or tamper with application state."
                    ),
                    remediation=(
                        "Use an explicit input allowlist (e.g., a DTO/schema) that only permits "
                        "expected fields. Strip unexpected fields server-side before object binding. "
                        "Never bind raw request bodies directly to ORM models."
                    ),
                    endpoint_method=endpoint.method,
                    endpoint_path=endpoint.path,
                    evidence_request=f"{endpoint.method} {endpoint.full_url}\n{json.dumps(inject_payload, indent=2)}",
                    evidence_response=self.format_evidence_response(resp),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                        "https://cwe.mitre.org/data/definitions/915.html",
                    ],
                ))
        return findings
