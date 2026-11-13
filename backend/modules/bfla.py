"""
API5:2023 — Broken Function Level Authorization (BFLA)
Tests: low-priv token accessing admin endpoints, HTTP method tampering.
"""
from __future__ import annotations
import httpx

from modules.base import BaseModule, Endpoint, ScanConfig
from engine.finding import Finding, Severity
from engine.session_manager import SessionContext

ADMIN_PATH_PATTERNS = [
    "/admin", "/administrator", "/manage", "/management",
    "/internal", "/private", "/staff", "/superuser",
    "/api/admin", "/api/internal",
]

HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]


class BflaModule(BaseModule):
    name = "bfla"
    title = "Broken Function Level Authorization (BFLA)"
    owasp_category = "API5:2023"
    cwe_ids = ["CWE-285", "CWE-269"]
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

        # 1. Method tampering — try HTTP methods the endpoint doesn't declare
        findings.extend(
            await self._test_method_tampering(endpoint, session, config, client)
        )

        # 2. Admin endpoint access with low-priv token
        for pattern in ADMIN_PATH_PATTERNS:
            if endpoint.path.lower().startswith(pattern):
                findings.extend(
                    await self._test_admin_access(endpoint, session, config, client)
                )
                break

        return findings

    async def _test_method_tampering(
        self, endpoint: Endpoint, session: SessionContext,
        config: ScanConfig, client: httpx.AsyncClient,
    ) -> list[Finding]:
        findings = []
        declared_method = endpoint.method.upper()
        req_kwargs = session.apply({"headers": {}})

        for method in HTTP_METHODS:
            if method == declared_method:
                continue
            try:
                resp = await client.request(
                    method, endpoint.full_url,
                    timeout=10, **req_kwargs
                )
                # Skip HTML SPA pages or standard unmapped/method not allowed responses
                if self.is_html_or_spa_response(resp) or self.is_unmapped_api_response(resp):
                    continue

                # If an undeclared method succeeds (HTTP 200/201/204), flag it
                if resp.status_code in (200, 201, 204):
                    findings.append(self._build_finding(
                        title=f"HTTP Method Tampering: {method} Accepted on {declared_method}-Only Endpoint",
                        severity=Severity.MEDIUM,
                        cvss_score=6.5,
                        description=(
                            f"The endpoint `{endpoint.path}` is documented as {declared_method}, "
                            f"but successfully accepts {method} with HTTP {resp.status_code}."
                        ),
                        business_impact=(
                            "Undocumented HTTP methods may bypass authorization logic "
                            "(e.g., a read-only endpoint also accepting DELETE or mutating operations)."
                        ),
                        remediation=(
                            "Explicitly restrict accepted HTTP methods server-side. "
                            "Return 405 Method Not Allowed for all undeclared methods."
                        ),
                        endpoint_method=method,
                        endpoint_path=endpoint.path,
                        evidence_request=f"{method} {endpoint.full_url}",
                        evidence_response=self.format_evidence_response(resp),
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
                        ],
                    ))
            except Exception:
                continue
        return findings

    async def _test_admin_access(
        self, endpoint: Endpoint, session: SessionContext,
        config: ScanConfig, client: httpx.AsyncClient,
    ) -> list[Finding]:
        """Check if current (possibly low-priv) session can access admin endpoints."""
        findings = []
        req_kwargs = session.apply({"headers": {}})
        try:
            resp = await client.request(
                endpoint.method, endpoint.full_url,
                timeout=config.timeout, **req_kwargs
            )
            # Filter out SPA fallback HTML
            if self.is_html_or_spa_response(resp) or self.is_unmapped_api_response(resp):
                return findings

            if resp.status_code in (200, 201):
                findings.append(self._build_finding(
                    title="Admin/Privileged Endpoint Accessible with Current Credentials",
                    severity=Severity.CRITICAL,
                    cvss_score=9.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                    description=(
                        f"The admin endpoint `{endpoint.path}` returned HTTP {resp.status_code} "
                        "with the provided credentials. This may indicate insufficient function-level authorization."
                    ),
                    business_impact=(
                        "Attackers with any valid account can access admin functionality, "
                        "potentially modifying system configuration, data, or user accounts."
                    ),
                    remediation=(
                        "Implement role-based access control (RBAC) and verify the user's role "
                        "on every admin endpoint request. Do not rely on URL obscurity."
                    ),
                    endpoint_method=endpoint.method,
                    endpoint_path=endpoint.path,
                    evidence_request=f"{endpoint.method} {endpoint.full_url}",
                    evidence_response=self.format_evidence_response(resp),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
                    ],
                ))
        except Exception:
            pass
        return findings
