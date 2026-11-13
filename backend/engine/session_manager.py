"""
Auth/Session Manager — supports Bearer, API Key, Basic, Cookie, OAuth2 client-credentials.
Manages multiple auth "roles" (e.g. low-priv vs admin) for BOLA/BFLA testing.
"""
from __future__ import annotations
import base64
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import httpx


class AuthType(str, Enum):
    NONE       = "none"
    BEARER     = "bearer"
    API_KEY    = "api_key"
    BASIC      = "basic"
    COOKIE     = "cookie"
    OAUTH2_CC  = "oauth2_client_credentials"


@dataclass
class AuthConfig:
    """Auth configuration supplied by the user per role."""
    role_name: str              # e.g. "admin", "user", "anonymous"
    auth_type: AuthType = AuthType.NONE

    # Bearer / OAuth2
    token: str = ""

    # API Key
    api_key: str = ""
    api_key_header: str = "X-API-Key"
    api_key_query_param: str = ""    # alternative: pass in query string

    # Basic auth
    username: str = ""
    password: str = ""

    # Cookie
    cookies: dict[str, str] = field(default_factory=dict)

    # OAuth2 client-credentials
    token_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    scope: str = ""

    # Extra headers to inject (e.g. X-Tenant-ID)
    extra_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class SessionContext:
    """A resolved session context ready to be applied to HTTP requests."""
    role_name: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)

    def apply(self, request_kwargs: dict[str, Any]) -> dict[str, Any]:
        """Merge auth into a prepared request kwargs dict."""
        headers = {**self.headers, **request_kwargs.get("headers", {})}
        cookies = {**self.cookies, **request_kwargs.get("cookies", {})}
        params  = {**self.params,  **request_kwargs.get("params",  {})}
        return {**request_kwargs, "headers": headers, "cookies": cookies, "params": params}


class SessionManager:
    """Resolves AuthConfig → SessionContext, including token fetching for OAuth2."""

    def __init__(self, configs: list[AuthConfig]):
        self._configs = {c.role_name: c for c in configs}
        self._contexts: dict[str, SessionContext] = {}

    async def initialize(self) -> None:
        """Resolve all auth configs (fetch OAuth2 tokens if needed)."""
        for role_name, cfg in self._configs.items():
            ctx = await self._resolve(cfg)
            self._contexts[role_name] = ctx

    async def _resolve(self, cfg: AuthConfig) -> SessionContext:
        headers: dict[str, str] = {}
        cookies: dict[str, str] = {}
        params:  dict[str, str] = {}

        if cfg.auth_type == AuthType.BEARER and cfg.token:
            headers["Authorization"] = f"Bearer {cfg.token}"

        elif cfg.auth_type == AuthType.API_KEY and cfg.api_key:
            if cfg.api_key_query_param:
                params[cfg.api_key_query_param] = cfg.api_key
            else:
                headers[cfg.api_key_header] = cfg.api_key

        elif cfg.auth_type == AuthType.BASIC and cfg.username:
            raw = f"{cfg.username}:{cfg.password}"
            encoded = base64.b64encode(raw.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"

        elif cfg.auth_type == AuthType.COOKIE and cfg.cookies:
            cookies = dict(cfg.cookies)

        elif cfg.auth_type == AuthType.OAUTH2_CC and cfg.token_url:
            token = await self._fetch_oauth2_token(cfg)
            if token:
                headers["Authorization"] = f"Bearer {token}"

        # Merge extra headers
        headers.update(cfg.extra_headers)

        return SessionContext(
            role_name=cfg.role_name,
            headers=headers,
            cookies=cookies,
            params=params,
        )

    async def _fetch_oauth2_token(self, cfg: AuthConfig) -> str:
        """Fetch an OAuth2 client-credentials token."""
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                data = {
                    "grant_type": "client_credentials",
                    "client_id": cfg.client_id,
                    "client_secret": cfg.client_secret,
                }
                if cfg.scope:
                    data["scope"] = cfg.scope
                resp = await client.post(cfg.token_url, data=data)
                resp.raise_for_status()
                return resp.json().get("access_token", "")
            except Exception as e:
                print(f"[SessionManager] OAuth2 token fetch failed for {cfg.role_name}: {e}")
                return ""

    def get_context(self, role_name: str) -> SessionContext | None:
        return self._contexts.get(role_name)

    def all_contexts(self) -> list[SessionContext]:
        return list(self._contexts.values())

    def primary_context(self) -> SessionContext:
        """Return the first (primary) session context."""
        if not self._contexts:
            return SessionContext(role_name="anonymous")
        return next(iter(self._contexts.values()))
