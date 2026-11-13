"""
NoSQL Injection, Command Injection, XSS, Rate Limit, CORS,
Input Fuzzing, JWT Attacks, and API Inventory modules.
"""
from __future__ import annotations
import json
import re
import time
import base64
import httpx

from modules.base import BaseModule, Endpoint, ScanConfig
from engine.finding import Finding, Severity
from engine.session_manager import SessionContext


# ─────────────────────────────────────────────────────────────────────────────
# NoSQL Injection
# ─────────────────────────────────────────────────────────────────────────────

NOSQL_PAYLOADS = [
    {"$gt": ""},
    {"$ne": None},
    {"$regex": ".*"},
    {"$where": "1==1"},
]


class NoSqliModule(BaseModule):
    name = "nosqli"
    title = "NoSQL Injection"
    owasp_category = "API10:2023"
    cwe_ids = ["CWE-943"]
    severity_default = Severity.HIGH
    safe_mode_compatible = True
    destructive = False

    async def run(self, endpoint, session, config, client):
        findings = []
        if not self.is_enabled(config):
            return findings
        if endpoint.method.upper() not in ("POST", "PUT", "PATCH"):
            return findings

        for payload in NOSQL_PAYLOADS:
            req_kwargs = session.apply({
                "headers": {"Content-Type": "application/json"},
                "content": json.dumps(payload).encode(),
            })
            try:
                resp = await client.request(
                    endpoint.method, endpoint.full_url, timeout=config.timeout, **req_kwargs
                )
                if resp.status_code in (200, 201):
                    # Filter out SPA HTML responses and unmapped 404s
                    if self.is_html_or_spa_response(resp) or self.is_unmapped_api_response(resp):
                        continue
                    try:
                        data = resp.json()
                        if isinstance(data, dict) and data.get("success") is False:
                            continue
                    except Exception:
                        pass

                    findings.append(self._build_finding(
                        title="Potential NoSQL Injection",
                        severity=Severity.HIGH,
                        cvss_score=8.5,
                        description=(
                            f"Payload `{json.dumps(payload)}` returned HTTP {resp.status_code}. "
                            "MongoDB-style operators ($gt, $ne) were accepted by the backend."
                        ),
                        business_impact="NoSQL injection can bypass authentication, expose all records, or corrupt data.",
                        remediation=(
                            "Validate and sanitize input to reject MongoDB operator keys ($gt, $ne, $regex). "
                            "Use an ORM or query builder that escapes operators."
                        ),
                        endpoint_method=endpoint.method,
                        endpoint_path=endpoint.path,
                        evidence_request=f"{endpoint.method} {endpoint.full_url}\n{json.dumps(payload)}",
                        evidence_response=self.format_evidence_response(resp),
                        references=["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"],
                    ))
                    break
            except Exception:
                continue
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Command Injection
# ─────────────────────────────────────────────────────────────────────────────

CMDI_PAYLOADS = [
    "; id",
    "| id",
    "` id`",
    "$(id)",
    "; sleep 5",
    "| sleep 5",
    "& ping -c 1 127.0.0.1",
]

CMDI_RESPONSE_MARKERS = [
    "uid=", "gid=", "root:", "/bin/", "www-data",
    "command not found", "/usr/bin",
]


class CmdiModule(BaseModule):
    name = "cmdi"
    title = "Command Injection"
    owasp_category = "API10:2023"
    cwe_ids = ["CWE-78"]
    severity_default = Severity.CRITICAL
    safe_mode_compatible = True
    destructive = False

    async def run(self, endpoint, session, config, client):
        findings = []
        if not self.is_enabled(config):
            return findings

        for param in endpoint.parameters:
            if param.get("in") not in ("query", "path"):
                continue
            param_name = param.get("name", "")
            for payload in CMDI_PAYLOADS:
                req_kwargs = session.apply({"params": {param_name: payload}})
                try:
                    t0 = time.monotonic()
                    resp = await client.request(
                        endpoint.method, endpoint.full_url, timeout=max(config.timeout, 15), **req_kwargs
                    )
                    elapsed = time.monotonic() - t0
                    body_lower = resp.text.lower()

                    if any(m in body_lower for m in CMDI_RESPONSE_MARKERS):
                        findings.append(self._build_finding(
                            title=f"Command Injection — Parameter `{param_name}`",
                            severity=Severity.CRITICAL,
                            cvss_score=10.0,
                            description=f"Command injection confirmed via `{param_name}`. Response contained OS output.",
                            business_impact="Full server compromise — attacker can execute arbitrary OS commands.",
                            remediation="Never pass user input to OS commands. Use safe APIs and strict input validation.",
                            endpoint_method=endpoint.method,
                            endpoint_path=endpoint.path,
                            evidence_request=f"{endpoint.method} {endpoint.full_url}\n{param_name}={payload}",
                            evidence_response=f"HTTP {resp.status_code}\n{resp.text[:400]}",
                            references=["https://owasp.org/www-community/attacks/Command_Injection"],
                        ))
                        break
                    if "sleep" in payload and elapsed >= 4.5:
                        findings.append(self._build_finding(
                            title=f"Command Injection (Time-Based) — Parameter `{param_name}`",
                            severity=Severity.CRITICAL,
                            cvss_score=10.0,
                            description=f"Sleep payload caused {elapsed:.1f}s delay, indicating command injection.",
                            business_impact="Full server compromise.",
                            remediation="Never pass user input to OS commands.",
                            endpoint_method=endpoint.method,
                            endpoint_path=endpoint.path,
                            evidence_request=f"{endpoint.method} {endpoint.full_url}\n{param_name}={payload}",
                            evidence_response=f"HTTP {resp.status_code} (response time: {elapsed:.1f}s)",
                        ))
                        break
                except Exception:
                    continue
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Reflected XSS
# ─────────────────────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
]


class XssModule(BaseModule):
    name = "xss"
    title = "Reflected XSS"
    owasp_category = "API10:2023"
    cwe_ids = ["CWE-79"]
    severity_default = Severity.MEDIUM
    safe_mode_compatible = True
    destructive = False

    async def run(self, endpoint, session, config, client):
        findings = []
        if not self.is_enabled(config):
            return findings

        for param in endpoint.parameters:
            if param.get("in") not in ("query",):
                continue
            param_name = param.get("name", "")
            for payload in XSS_PAYLOADS:
                req_kwargs = session.apply({"params": {param_name: payload}})
                try:
                    resp = await client.request(
                        endpoint.method, endpoint.full_url, timeout=config.timeout, **req_kwargs
                    )
                    # Check for unescaped reflection
                    if payload in resp.text:
                        ct = resp.headers.get("content-type", "")
                        if "html" in ct or "json" in ct:
                            findings.append(self._build_finding(
                                title=f"Reflected XSS — Parameter `{param_name}`",
                                severity=Severity.MEDIUM,
                                cvss_score=6.1,
                                description=f"XSS payload was reflected unescaped in the response via `{param_name}`.",
                                business_impact="Attackers can execute scripts in victims' browsers, stealing sessions or data.",
                                remediation="HTML-encode all user-supplied data before embedding in responses. Set a strict CSP.",
                                endpoint_method=endpoint.method,
                                endpoint_path=endpoint.path,
                                evidence_request=f"{endpoint.method} {endpoint.full_url}\n{param_name}={payload}",
                                evidence_response=f"HTTP {resp.status_code}\n{resp.text[:400]}",
                                references=["https://owasp.org/www-community/attacks/xss/"],
                            ))
                            break
                except Exception:
                    continue
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Rate Limiting / Resource Consumption
# ─────────────────────────────────────────────────────────────────────────────

class RateLimitModule(BaseModule):
    name = "rate_limit"
    title = "Unrestricted Resource Consumption"
    owasp_category = "API4:2023"
    cwe_ids = ["CWE-770"]
    severity_default = Severity.MEDIUM
    safe_mode_compatible = True
    destructive = False

    async def run(self, endpoint, session, config, client):
        findings = []
        if not self.is_enabled(config):
            return findings

        # Send 20 rapid requests and check for rate-limiting. A server error or
        # authorization failure is inconclusive; it is not evidence of abuse.
        blocked = False
        completed_requests = 0
        successful_responses = 0
        req_kwargs = session.apply({"headers": {}})
        first_resp = None
        for _ in range(20):
            try:
                resp = await client.request(
                    endpoint.method, endpoint.full_url, timeout=5, **req_kwargs
                )
                completed_requests += 1
                if first_resp is None:
                    first_resp = resp
                if resp.status_code == 429 or resp.headers.get("retry-after"):
                    blocked = True
                    break
                if 200 <= resp.status_code < 400:
                    successful_responses += 1
            except Exception:
                break

        # If endpoint returns 404/Route Not Found or HTML SPA page, it's not a live API endpoint to rate limit
        if first_resp is None or self.is_html_or_spa_response(first_resp) or self.is_unmapped_api_response(first_resp):
            return findings

        # Only report when the endpoint accepted the test traffic. Responses
        # such as 401, 403, 429, or 5xx do not establish unrestricted use.
        if not blocked and completed_requests == 20 and successful_responses == 20:
            findings.append(self._build_finding(
                title="Missing Rate Limiting / Unrestricted Resource Consumption",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                description="20 rapid requests were sent to this active endpoint with no rate-limit response (HTTP 429) or throttling header observed.",
                business_impact="API can be abused to exhaust resources, harvest data at scale, or DoS the service.",
                remediation="Implement rate limiting per IP and per user token. Return HTTP 429 with Retry-After header.",
                endpoint_method=endpoint.method,
                endpoint_path=endpoint.path,
                evidence_request=f"20x {endpoint.method} {endpoint.full_url}",
                evidence_response=(
                    f"Sent 20 consecutive successful requests without server-side throttling.\n"
                    f"Latest response status: HTTP {first_resp.status_code} ({first_resp.headers.get('content-type', '')})\n"
                    f"Rate-limit headers present: {'None' if not any('ratelimit' in h.lower() for h in first_resp.headers) else 'Yes'}"
                ),
                references=["https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"],
            ))
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# CORS Misconfiguration
# ─────────────────────────────────────────────────────────────────────────────

class CorsModule(BaseModule):
    name = "cors"
    title = "CORS Misconfiguration"
    owasp_category = "API8:2023"
    cwe_ids = ["CWE-942"]
    severity_default = Severity.HIGH
    safe_mode_compatible = True
    destructive = False

    async def run(self, endpoint, session, config, client):
        findings = []
        if not self.is_enabled(config):
            return findings

        if not hasattr(self, "_cors_counts"):
            self._cors_counts: dict[str, int] = {}
        if self._cors_counts.get(config.scan_id, 0) >= 3:
            return findings

        EVIL_ORIGINS = [
            "https://evil.com",
            "null",
            f"https://attacker.{config.target_base_url.split('.')[-1] if '.' in config.target_base_url else 'com'}",
        ]

        for origin in EVIL_ORIGINS:
            req_kwargs = session.apply({"headers": {"Origin": origin}})
            try:
                resp = await client.request(
                    endpoint.method, endpoint.full_url, timeout=10, **req_kwargs
                )
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "").lower()

                if acao == origin or acao == "*":
                    self._cors_counts[config.scan_id] = self._cors_counts.get(config.scan_id, 0) + 1
                    sev = Severity.HIGH if acac == "true" else Severity.MEDIUM
                    score = 8.1 if acac == "true" else 5.4
                    findings.append(self._build_finding(
                        title=f"CORS: Arbitrary Origin Reflected — {origin}",
                        severity=sev,
                        cvss_score=score,
                        description=(
                            f"The server reflected `{origin}` in Access-Control-Allow-Origin. "
                            f"Credentials allowed: {acac}."
                        ),
                        business_impact="Cross-origin requests can read API responses from malicious websites.",
                        remediation="Maintain an explicit allowlist of trusted origins. Never reflect arbitrary origins.",
                        endpoint_method=endpoint.method,
                        endpoint_path=endpoint.path,
                        evidence_request=f"{endpoint.method} {endpoint.full_url}\nOrigin: {origin}",
                        evidence_response=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                        references=["https://portswigger.net/web-security/cors"],
                    ))
                    break
            except Exception:
                continue
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# JWT-Specific Attacks
# ─────────────────────────────────────────────────────────────────────────────

class JwtAttacksModule(BaseModule):
    name = "jwt_attacks"
    title = "JWT-Specific Attacks"
    owasp_category = "API2:2023"
    cwe_ids = ["CWE-327", "CWE-347"]
    severity_default = Severity.HIGH
    safe_mode_compatible = True
    destructive = False

    async def run(self, endpoint, session, config, client):
        findings = []
        if not self.is_enabled(config):
            return findings

        bearer = session.headers.get("Authorization", "")
        if not bearer.startswith("Bearer "):
            return findings

        token = bearer[7:]
        parts = token.split(".")
        if len(parts) != 3:
            return findings

        # Test kid header injection
        findings.extend(await self._test_kid_injection(endpoint, token, session, config, client))

        return findings

    async def _test_kid_injection(self, endpoint, token, session, config, client):
        """Test kid (key ID) header injection for path traversal."""
        findings = []
        try:
            header_b64 = parts[0] if (parts := token.split(".")) else ""
            header_b64 += "=" * (-len(header_b64) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            if "kid" in header:
                # Inject path traversal into kid
                kid_payload = "../../../../dev/null"
                forged_header = {**header, "kid": kid_payload}
                new_header = base64.urlsafe_b64encode(
                    json.dumps(forged_header, separators=(",", ":")).encode()
                ).rstrip(b"=").decode()
                forged_token = f"{new_header}.{token.split('.')[1]}."
                req_kwargs = session.apply({"headers": {"Authorization": f"Bearer {forged_token}"}})
                resp = await client.request(
                    endpoint.method, endpoint.full_url, timeout=config.timeout, **req_kwargs
                )
                if resp.status_code in (200, 201):
                    findings.append(self._build_finding(
                        title="JWT kid Header Path Traversal Accepted",
                        severity=Severity.CRITICAL,
                        cvss_score=9.8,
                        description="Server accepted a JWT with a path-traversal kid header, enabling auth bypass.",
                        business_impact="Attacker can forge arbitrary JWT payloads.",
                        remediation="Validate and sanitize the `kid` header. Use a key lookup by ID, not file path.",
                        endpoint_method=endpoint.method,
                        endpoint_path=endpoint.path,
                        evidence_request=f"{endpoint.method} {endpoint.full_url}\nAuthorization: Bearer <forged-kid-token>",
                        evidence_response=f"HTTP {resp.status_code}",
                    ))
        except Exception:
            pass
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# API Inventory (Shadow / Deprecated APIs)
# ─────────────────────────────────────────────────────────────────────────────

VERSION_PATTERNS = [
    "/v1/", "/v2/", "/v3/", "/api/v1/", "/api/v2/",
    "/v1.0/", "/v2.0/", "/version1/",
]


class InventoryModule(BaseModule):
    name = "inventory"
    title = "Improper API Inventory Management"
    owasp_category = "API9:2023"
    cwe_ids = ["CWE-1059"]
    severity_default = Severity.MEDIUM
    safe_mode_compatible = True
    destructive = False

    async def run(self, endpoint, session, config, client):
        findings = []
        if not self.is_enabled(config):
            return findings

        # Try deprecated versions of the current endpoint
        for ver in VERSION_PATTERNS:
            if ver in endpoint.path:
                # Find and try earlier version
                for alt_ver in VERSION_PATTERNS:
                    if alt_ver != ver and alt_ver in endpoint.path:
                        continue
                    alt_url = endpoint.full_url.replace(ver, alt_ver)
                    if alt_url == endpoint.full_url:
                        continue
                    req_kwargs = session.apply({"headers": {}})
                    try:
                        resp = await client.request(
                            endpoint.method, alt_url, timeout=10, **req_kwargs
                        )
                        # Filter out Single Page Application fallback HTML and unmapped routes
                        if self.is_html_or_spa_response(resp) or self.is_unmapped_api_response(resp):
                            continue

                        if resp.status_code in (200, 201):
                            findings.append(self._build_finding(
                                title=f"Shadow/Deprecated API Version Active: {alt_ver}",
                                severity=Severity.MEDIUM,
                                cvss_score=5.3,
                                description=(
                                    f"An older API version (`{alt_ver}`) is actively responding at `{alt_url}`. "
                                    "Old API versions may lack current security controls."
                                ),
                                business_impact="Deprecated APIs often miss security patches, enabling attackers to exploit old vulnerabilities.",
                                remediation="Decommission deprecated API versions. Implement version lifecycle policies.",
                                endpoint_method=endpoint.method,
                                endpoint_path=alt_url,
                                evidence_request=f"{endpoint.method} {alt_url}",
                                evidence_response=self.format_evidence_response(resp),
                                references=["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
                            ))
                    except Exception:
                        continue
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Input Validation Fuzzing
# ─────────────────────────────────────────────────────────────────────────────

FUZZ_PAYLOADS = [
    "A" * 10000,          # Oversized string
    -1,                    # Negative number
    0,                     # Zero
    2**31,                 # Integer overflow
    None,                  # Null
    [],                    # Wrong type (array)
    {},                    # Wrong type (object)
    "../../../etc/passwd", # Path traversal
    "%00",                 # Null byte
    "\x00\x01\x02",       # Binary
    "' OR 1=1",           # SQLi via fuzzer
    "<script>",            # XSS via fuzzer
]


class InputFuzzingModule(BaseModule):
    name = "input_fuzzing"
    title = "Input Validation Fuzzing"
    owasp_category = "API10:2023"
    cwe_ids = ["CWE-20"]
    severity_default = Severity.LOW
    safe_mode_compatible = True
    destructive = False

    async def run(self, endpoint, session, config, client):
        findings = []
        if not self.is_enabled(config):
            return findings

        for param in endpoint.parameters[:3]:  # Limit to first 3 params
            param_name = param.get("name", "")
            for payload in FUZZ_PAYLOADS[:6]:  # Limit payloads
                try:
                    req_kwargs = session.apply({"params": {param_name: str(payload)}})
                    resp = await client.request(
                        endpoint.method, endpoint.full_url, timeout=10, **req_kwargs
                    )
                    if resp.status_code == 500:
                        findings.append(self._build_finding(
                            title=f"Input Validation Error (HTTP 500) — Parameter `{param_name}`",
                            severity=Severity.LOW,
                            description=f"Fuzz payload `{str(payload)[:50]}` caused HTTP 500. Server may not validate input properly.",
                            business_impact="Unhandled exceptions can leak information or cause service instability.",
                            remediation="Validate all input strictly. Return 400 Bad Request for invalid input, not 500.",
                            endpoint_method=endpoint.method,
                            endpoint_path=endpoint.path,
                            evidence_request=f"{endpoint.method} {endpoint.full_url}\n{param_name}={str(payload)[:50]}",
                            evidence_response=f"HTTP {resp.status_code}",
                        ))
                        break
                except Exception:
                    continue
        return findings
