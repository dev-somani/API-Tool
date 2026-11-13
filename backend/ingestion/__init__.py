"""Ingestion package."""
from ingestion.openapi_parser import parse_openapi
from ingestion.postman_parser import parse_postman
from ingestion.manual_parser import parse_manual

__all__ = ["parse_openapi", "parse_postman", "parse_manual"]
