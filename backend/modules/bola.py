"""
API1:2023 — Broken Object Level Authorization (BOLA / IDOR)
Tests whether User A can access User B's resources by iterating object IDs.
"""
from __future__ import annotations
import re
import httpx

from modules.base import BaseModule, Endpoint, ScanConfig
from engine.finding import Finding, Severity
from engine.session_manager import SessionContext

# Regex to find ID-like path segments
ID_PATTERN = re.compile(
    r"(\{[^}]+\}|"                         # {param}
    r"\b\d{1,12}\b|"                       # numeric ID
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b)"  # UUID
)

SEQUENTIAL_IDS = ["1", "2", "3", "100", "999", "9999", "0"]
PROBE_UUIDS = [
    "00000000-0000-0000-0000-000000000001",
    "00000000-0000-0000-0000-000000000002",
]


def _substitute_id(path: str, new_id: str) -> str:
    """Replace the first ID-like segment in a URL path."""
    return ID_PATTERN.sub(new_id, path, count=1)


class BolaModule(BaseModule):
    name = "bola"
    title = "Broken Object Level Authorization (BOLA/IDOR)"
    owasp_category = "API1:2023"
    cwe_ids = ["CWE-284", "CWE-639"]
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
        if not self.is_enabled(config) or not self.is_safe_to_run(config):
            return findings

        if not ID_PATTERN.search(endpoint.full_url):
            return findings  # No ID-like params, skip

        # 1. Send a baseline request to get the "owned" object response
        req_kwargs = session.apply({"headers": {}})
        try:
            baseline = await client.request(
                endpoint.method, endpoint.full_url,
                timeout=config.timeout, **req_kwargs
            )
        except Exception:
            return findings

        if baseline.status_code not in (200, 201, 204):
            return findings  # No baseline access, skip

        # If baseline is HTML (SPA frontend fallback), skip — not an API endpoint
        if self.is_html_or_spa_response(baseline) or self.is_unmapped_api_response(baseline):
            return findings

        # 2. Try sequential IDs in place of the existing one
        probe_ids = SEQUENTIAL_IDS + PROBE_UUIDS
        for probe_id in probe_ids:
            mutated_url = _substitute_id(endpoint.full_url, probe_id)
            if mutated_url == endpoint.full_url:
                continue  # No substitution occurred

            try:
                resp = await client.request(
                    endpoint.method, mutated_url,
                    timeout=config.timeout, **req_kwargs
                )
            except Exception:
                continue

            # Skip HTML pages and route-not-found responses
            if self.is_html_or_spa_response(resp) or self.is_unmapped_api_response(resp):
                continue

            if resp.status_code in (200, 201):
                # Verify that response is valid JSON data and not a generic error
                try:
                    data = resp.json()
                    if isinstance(data, dict) and data.get("success") is False:
                        continue
                except Exception:
                    pass

                findings.append(self._build_finding(
                    title="Potential BOLA/IDOR Vulnerability",
                    severity=Severity.HIGH,
                    cvss_score=8.6,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
                    description=(
                        f"The endpoint `{endpoint.path}` returned HTTP {resp.status_code} with valid object data "
                        f"when an arbitrary object ID (`{probe_id}`) was requested without authorization. "
                        "Users can access other users' private objects by enumerating identifiers."
                    ),
                    business_impact=(
                        "Attackers can enumerate object IDs to access, modify, or exfiltrate "
                        "other users' private records and accounts."
                    ),
                    remediation=(
                        "Implement strict object-level access control on the server side. Verify that "
                        "the authenticated user identity in the session/JWT owns or is explicitly authorized "
                        "to read the requested resource ID."
                    ),
                    endpoint_method=endpoint.method,
                    endpoint_path=endpoint.path,
                    evidence_request=f"{endpoint.method} {mutated_url}",
                    evidence_response=self.format_evidence_response(resp),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                        "https://cwe.mitre.org/data/definitions/284.html",
                    ],
                ))
                break  # One confirmed finding per endpoint is sufficient

        return findings
