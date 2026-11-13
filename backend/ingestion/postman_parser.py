"""
Postman Collection v2.0 / v2.1 parser with robust variable substitution.
"""
from __future__ import annotations
import json
import re
from urllib.parse import urlparse
from modules.base import Endpoint


def _extract_items(items: list, base_url: str, endpoints: list[Endpoint]):
    """Recursively extract requests from Postman folder tree."""
    clean_base = base_url.rstrip("/")

    for item in items:
        if "item" in item:
            # Folder — recurse
            _extract_items(item["item"], base_url, endpoints)
            continue

        request = item.get("request", {})
        if not request:
            continue

        method = request.get("method", "GET").upper()
        url_data = request.get("url", {})

        raw_url = ""
        path = "/"

        if isinstance(url_data, str):
            raw_url = url_data.strip()
        elif isinstance(url_data, dict):
            raw_url = url_data.get("raw", "").strip()
            if not raw_url:
                # Build from path array
                raw_parts = url_data.get("path", [])
                path = "/" + "/".join(
                    (f"{{{p['value']}}}" if isinstance(p, dict) and p.get("type") == "variable"
                     else str(p) if not isinstance(p, dict) else p.get("value", ""))
                    for p in raw_parts
                )
                host = url_data.get("host", [])
                if host:
                    host_str = ".".join(host) if isinstance(host, list) else str(host)
                    if host_str.startswith("{{") or host_str in ("baseUrl", "base_url", "url", "host"):
                        raw_url = f"{clean_base}{path}"
                    else:
                        scheme = url_data.get("protocol", "https")
                        raw_url = f"{scheme}://{host_str}{path}"
                else:
                    raw_url = f"{clean_base}{path}"

        # Substitute any residual {{baseUrl}} or variants
        raw_url = re.sub(r"\{\{\s*(?:base_?url|host|url)\s*\}\}", clean_base, raw_url, flags=re.IGNORECASE)

        # Parse scheme & host
        parsed = urlparse(raw_url)
        if parsed.scheme and parsed.netloc:
            full_url = raw_url
            path = parsed.path or "/"
        else:
            path = "/" + raw_url.lstrip("/")
            full_url = f"{clean_base}{path}"

        # Query parameters
        query_params = []
        if isinstance(url_data, dict):
            for q in url_data.get("query", []):
                query_params.append({
                    "name": q.get("key", ""),
                    "in": "query",
                    "schema": {"type": "string"},
                })

        # Headers
        headers = {}
        for h in request.get("header", []):
            if isinstance(h, dict):
                headers[h.get("key", "")] = h.get("value", "")

        # Body
        req_body_schema = None
        body = request.get("body", {})
        if body:
            mode = body.get("mode", "")
            if mode == "raw":
                raw_body = body.get("raw", "")
                try:
                    parsed_body = json.loads(raw_body)
                    if isinstance(parsed_body, dict):
                        req_body_schema = {
                            "type": "object",
                            "properties": {k: {"type": "string"} for k in parsed_body},
                        }
                except Exception:
                    pass
            elif mode == "urlencoded":
                req_body_schema = {
                    "type": "object",
                    "properties": {
                        item.get("key", ""): {"type": "string"}
                        for item in body.get("urlencoded", [])
                    },
                }

        endpoints.append(Endpoint(
            method=method,
            path=path,
            full_url=full_url,
            parameters=query_params,
            request_body_schema=req_body_schema,
            tags=[],
            summary=item.get("name", ""),
            requires_auth="authorization" in {k.lower() for k in headers},
        ))


def parse_postman(content: str, base_url: str) -> list[Endpoint]:
    """Parse a Postman Collection v2.0/v2.1 JSON string with variable substitution."""
    clean_base = base_url.rstrip("/")

    # 1. Substitute collection-level variables
    try:
        raw_json = json.loads(content)
        for var in raw_json.get("variable", []):
            key = var.get("key")
            val = str(var.get("value", ""))
            if key and val:
                pattern = re.compile(r"\{\{\s*" + re.escape(key) + r"\s*\}\}")
                content = pattern.sub(val, content)
    except Exception:
        pass

    # 2. Always substitute standard baseUrl placeholders with target base_url
    content = re.sub(r"\{\{\s*(?:base_?url|host|url)\s*\}\}", clean_base, content, flags=re.IGNORECASE)

    data = json.loads(content)
    endpoints: list[Endpoint] = []
    items = data.get("item", [])
    _extract_items(items, clean_base, endpoints)
    return endpoints
