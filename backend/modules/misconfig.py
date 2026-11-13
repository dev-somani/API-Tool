"""
API8 — Security Misconfiguration (Passive)
Checks: missing security headers, CORS wildcard, verbose errors,
exposed debug/docs endpoints, unnecessary HTTP methods.
"""
from __future__ import annotations
import httpx

from modules.base import BaseModule, Endpoint, ScanConfig
from engine.finding import Finding, Severity
from engine.session_manager import SessionContext

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS not set — connections can be downgraded to HTTP"),
    ("X-Content-Type-Options", "Missing X-Content-Type-Options: nosniff — MIME-type sniffing possible"),
    ("X-Frame-Options", "Missing X-Frame-Options — clickjacking risk"),
    ("Content-Security-Policy", "Missing Content-Security-Policy — XSS mitigations absent"),
    ("Referrer-Policy", "Missing Referrer-Policy — sensitive URL data may leak in Referer header"),
    ("Permissions-Policy", "Missing Permissions-Policy header"),
]

SENSITIVE_ENDPOINTS = [
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api/docs", "/docs", "/redoc",
    "/.env", "/.git/config", "/config.json",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/info",
    "/actuator/beans", "/actuator/mappings", "/metrics", "/health",
    "/admin", "/console", "/phpinfo.php", "/server-status",
    "/graphql", "/graphiql", "/playground",
]

STACK_TRACE_MARKERS = [
    "traceback", "stack trace", "exception in thread",
    "at java.", "at org.", "at com.", "at net.",
    "sqlstate", "ora-", "pg::syntaxerror",
    "system.exception", "unhandled exception",
    "debug_backtrace", "fatal error in",
    "errno", "warning: include(",
]


class MisconfigModule(BaseModule):
    name = "misconfig"
    title = "Security Misconfiguration"
    owasp_category = "API8:2023"
    cwe_ids = ["CWE-16", "CWE-200"]
    severity_default = Severity.MEDIUM
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

        # 1. Send baseline request and inspect headers
        try:
            req_kwargs = session.apply({
                "headers": {"User-Agent": "VAPT-Tool/1.0"},
            })
            resp = await client.request(
                endpoint.method,
                endpoint.full_url,
                timeout=config.timeout,
                **req_kwargs,
            )
            findings.extend(self._check_security_headers(endpoint, resp, config))
            findings.extend(self._check_verbose_errors(endpoint, resp))
            findings.extend(self._check_cors(endpoint, resp, client, config, session))
        except Exception:
            pass

        # 2. Probe sensitive/debug endpoints (only on base URL)
        if endpoint.path in ("/", "") or endpoint.path == endpoint.full_url:
            findings.extend(
                await self._probe_sensitive_endpoints(endpoint, config, client, session)
            )

        # 3. HTTP method probing (TRACE)
        findings.extend(
            await self._check_trace_method(endpoint, config, client, session)
        )

        return findings

    def _check_security_headers(
        self, endpoint: Endpoint, resp: httpx.Response, config: ScanConfig
    ) -> list[Finding]:
        findings = []
        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        # Deduplicate per scan: report each missing header on at most 2 sample endpoints
        if not hasattr(self, "_header_counts"):
            self._header_counts: dict[str, dict[str, int]] = {}
        counts = self._header_counts.setdefault(config.scan_id, {})

        for header_name, message in SECURITY_HEADERS:
            if header_name.lower() not in resp_headers_lower:
                if counts.get(header_name, 0) >= 2:
                    continue
                counts[header_name] = counts.get(header_name, 0) + 1
                findings.append(self._build_finding(
                    title=f"Missing Security Header: {header_name}",
                    severity=Severity.LOW,
                    description=message,
                    business_impact=(
                        "Missing security headers weaken the browser/client security posture "
                        "and can allow cross-site scripting, clickjacking, MIME sniffing, "
                        "and protocol downgrade attacks."
                    ),
                    remediation=(
                        f"Add the `{header_name}` response header with an appropriate value. "
                        "Consult OWASP Secure Headers Project for recommended values."
                    ),
                    endpoint_method=endpoint.method,
                    endpoint_path=endpoint.path,
                    evidence_request=f"{endpoint.method} {endpoint.full_url}",
                    evidence_response=f"HTTP {resp.status_code}\n(Header absent: {header_name})",
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers",
                    ],
                ))
        return findings

    def _check_verbose_errors(
        self, endpoint: Endpoint, resp: httpx.Response
    ) -> list[Finding]:
        findings = []
        if resp.status_code >= 400:
            try:
                body = resp.text.lower()
            except Exception:
                return findings
            for marker in STACK_TRACE_MARKERS:
                if marker in body:
                    findings.append(self._build_finding(
                        title="Verbose Error / Stack Trace Exposed",
                        severity=Severity.MEDIUM,
                        description=(
                            f"The API returned a verbose error containing '{marker}', "
                            "suggesting stack traces or internal debug information is exposed."
                        ),
                        business_impact=(
                            "Stack traces reveal internal technology stack, file paths, and "
                            "code structure that attackers use to craft targeted attacks."
                        ),
                        remediation=(
                            "Configure the application to return generic error messages in production. "
                            "Never expose stack traces, database errors, or internal paths to clients."
                        ),
                        endpoint_method=endpoint.method,
                        endpoint_path=endpoint.path,
                        evidence_request=f"{endpoint.method} {endpoint.full_url}",
                        evidence_response=f"HTTP {resp.status_code}\n{resp.text[:500]}",
                        cvss_score=5.3,
                        references=["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"],
                    ))
                    break
        return findings

    def _check_cors(
        self, endpoint: Endpoint, resp: httpx.Response,
        client: httpx.AsyncClient, config: ScanConfig, session: SessionContext,
    ) -> list[Finding]:
        findings = []
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower()
        if acao == "*" and acac == "true":
            findings.append(self._build_finding(
                title="CORS Wildcard with Credentials Allowed",
                severity=Severity.HIGH,
                cvss_score=8.1,
                description=(
                    "The API responds with `Access-Control-Allow-Origin: *` combined with "
                    "`Access-Control-Allow-Credentials: true`. This combination is invalid per "
                    "the CORS spec but some libraries misimplement it, allowing cross-origin "
                    "cookie/credential theft."
                ),
                business_impact=(
                    "Any malicious website can send authenticated requests to this API on behalf "
                    "of a logged-in user, potentially leading to account takeover or data exfiltration."
                ),
                remediation=(
                    "Never combine Access-Control-Allow-Origin: * with Allow-Credentials: true. "
                    "Use an explicit allowlist of trusted origins instead."
                ),
                endpoint_method=endpoint.method,
                endpoint_path=endpoint.path,
                evidence_response=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                references=["https://portswigger.net/web-security/cors"],
            ))
        return findings

    async def _probe_sensitive_endpoints(
        self, endpoint: Endpoint, config: ScanConfig,
        client: httpx.AsyncClient, session: SessionContext,
    ) -> list[Finding]:
        findings = []
        base = config.target_base_url.rstrip("/")
        req_kwargs = session.apply({"headers": {"User-Agent": "VAPT-Tool/1.0"}})

        for path in SENSITIVE_ENDPOINTS:
            url = f"{base}{path}"
            try:
                resp = await client.get(url, timeout=10, **req_kwargs)
                if resp.status_code in (200, 301, 302):
                    # Filter out Single Page Application fallback HTML pages
                    if self.is_html_or_spa_response(resp) or self.is_unmapped_api_response(resp):
                        continue

                    # Validate specific sensitive endpoint contents
                    text_lower = resp.text.lower()
                    if path == "/.env" and not any(k in resp.text for k in ("=", "APP_", "DB_", "SECRET", "KEY")):
                        continue
                    if "swagger" in path or "openapi" in path or "api-docs" in path:
                        if not any(k in text_lower for k in ("swagger", "openapi", '"paths"', 'paths:')):
                            continue
                    if "actuator" in path and not any(k in text_lower for k in ("status", "_links", "beans", "health")):
                        continue
                    if "phpinfo" in path and "php version" not in text_lower:
                        continue

                    findings.append(self._build_finding(
                        title=f"Sensitive Endpoint Exposed: {path}",
                        severity=Severity.HIGH if "actuator" in path or ".env" in path else Severity.MEDIUM,
                        description=(
                            f"The endpoint `{path}` returned HTTP {resp.status_code} with valid sensitive endpoint data, "
                            "suggesting it is accessible and may expose internal structure or credentials."
                        ),
                        business_impact=(
                            "Exposed debug, docs, or config endpoints reveal API structure, "
                            "credentials, and configuration to attackers."
                        ),
                        remediation=(
                            f"Disable or protect the `{path}` endpoint in production. "
                            "Use authentication/IP allowlisting for admin/debug routes."
                        ),
                        endpoint_method="GET",
                        endpoint_path=path,
                        evidence_request=f"GET {url}",
                        evidence_response=self.format_evidence_response(resp),
                        references=["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
                    ))
            except Exception:
                pass
        return findings

    async def _check_trace_method(
        self, endpoint: Endpoint, config: ScanConfig,
        client: httpx.AsyncClient, session: SessionContext,
    ) -> list[Finding]:
        findings = []
        req_kwargs = session.apply({"headers": {}})
        try:
            resp = await client.request("TRACE", endpoint.full_url, timeout=10, **req_kwargs)
            if resp.status_code < 400:
                findings.append(self._build_finding(
                    title="HTTP TRACE Method Enabled",
                    severity=Severity.LOW,
                    description=(
                        "The TRACE HTTP method is enabled, which can facilitate Cross-Site Tracing (XST) attacks."
                    ),
                    business_impact="Can be used to steal session cookies via XST attacks in combination with XSS.",
                    remediation="Disable the TRACE HTTP method in the web server/proxy configuration.",
                    endpoint_method="TRACE",
                    endpoint_path=endpoint.path,
                    evidence_request=f"TRACE {endpoint.full_url}",
                    evidence_response=f"HTTP {resp.status_code}",
                ))
        except Exception:
            pass
        return findings
