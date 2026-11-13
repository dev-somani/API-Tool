"""
Manual endpoint list parser.
Accepts a list of dicts or a newline-separated list of "METHOD URL" strings.
"""
from __future__ import annotations
from modules.base import Endpoint


def parse_manual(entries: list[dict], base_url: str) -> list[Endpoint]:
    """
    Parse manually entered endpoints.
    
    Each entry can be:
      { "method": "GET", "path": "/users/{id}", "parameters": [...], ... }
    or a simple string "GET /users/{id}"
    """
    endpoints = []
    base_url = base_url.rstrip("/")

    for entry in entries:
        if isinstance(entry, str):
            parts = entry.strip().split(" ", 1)
            if len(parts) == 2:
                method, path = parts
            else:
                continue
            entry = {"method": method, "path": path}

        method = entry.get("method", "GET").upper()
        path = entry.get("path", "/")
        if not path.startswith("/"):
            path = "/" + path

        full_url = entry.get("full_url") or f"{base_url}{path}"

        endpoints.append(Endpoint(
            method=method,
            path=path,
            full_url=full_url,
            parameters=entry.get("parameters", []),
            request_body_schema=entry.get("request_body_schema"),
            tags=entry.get("tags", []),
            summary=entry.get("summary", ""),
            requires_auth=entry.get("requires_auth", True),
        ))

    return endpoints
