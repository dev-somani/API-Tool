"""
OpenAPI 3.x / Swagger 2.0 spec parser.
Returns a list of Endpoint objects from a parsed spec dict.
"""
from __future__ import annotations
import json
import re
import yaml

from modules.base import Endpoint


def _load_spec(content: str) -> dict:
    """Auto-detect JSON or YAML and parse."""
    content = content.strip()
    if content.startswith("{"):
        return json.loads(content)
    return yaml.safe_load(content)


def _resolve_ref(ref: str, spec: dict) -> dict:
    """Resolve a simple $ref like '#/components/schemas/Foo'."""
    if not ref.startswith("#/"):
        return {}
    parts = ref.lstrip("#/").split("/")
    node = spec
    for part in parts:
        node = node.get(part, {})
    return node or {}


def _get_schema(schema_or_ref: dict, spec: dict) -> dict:
    if "$ref" in schema_or_ref:
        return _resolve_ref(schema_or_ref["$ref"], spec)
    return schema_or_ref


def parse_openapi(content: str, base_url: str) -> list[Endpoint]:
    """Parse OpenAPI 3.x or Swagger 2.0 spec into a list of Endpoints."""
    spec = _load_spec(content)
    endpoints: list[Endpoint] = []
    base_url = base_url.rstrip("/")

    # Determine spec version
    version = spec.get("openapi", spec.get("swagger", ""))
    is_swagger2 = version.startswith("2.")

    # Swagger 2 base path
    if is_swagger2:
        host = spec.get("host", "")
        scheme = spec.get("schemes", ["https"])[0]
        base_path = spec.get("basePath", "/")
        if host:
            base_url = f"{scheme}://{host}{base_path}".rstrip("/")

    paths = spec.get("paths", {})
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method in ["get", "post", "put", "patch", "delete", "head", "options"]:
            op = path_item.get(method)
            if not op:
                continue

            # Parameters
            params: list[dict] = []
            for p in (path_item.get("parameters", []) + op.get("parameters", [])):
                resolved = _get_schema(p, spec)
                params.append(resolved)

            # Request body
            req_body_schema = None
            if is_swagger2:
                for p in params:
                    if p.get("in") == "body":
                        req_body_schema = _get_schema(p.get("schema", {}), spec)
            else:
                rb = op.get("requestBody", {})
                if rb:
                    content_types = rb.get("content", {})
                    for ct in ["application/json", "application/x-www-form-urlencoded"]:
                        if ct in content_types:
                            raw = content_types[ct].get("schema", {})
                            req_body_schema = _get_schema(raw, spec)
                            break

            # Response schemas
            resp_schemas = {}
            for code, resp_def in op.get("responses", {}).items():
                resolved_resp = _get_schema(resp_def, spec)
                content_map = resolved_resp.get("content", {})
                for ct_key, ct_val in content_map.items():
                    if "json" in ct_key:
                        raw = ct_val.get("schema", {})
                        resp_schemas[str(code)] = _get_schema(raw, spec)
                        break

            # Security requirement
            sec = op.get("security", spec.get("security", []))
            requires_auth = len(sec) > 0

            full_url = f"{base_url}{path}"
            endpoints.append(Endpoint(
                method=method.upper(),
                path=path,
                full_url=full_url,
                parameters=[p for p in params if p.get("in") != "body"],
                request_body_schema=req_body_schema,
                response_schemas=resp_schemas,
                tags=op.get("tags", []),
                summary=op.get("summary", op.get("operationId", "")),
                requires_auth=requires_auth,
            ))

    return endpoints
