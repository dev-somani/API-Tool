"""
Module registry — auto-discovers and registers all detection modules.
"""
from modules.base import BaseModule
from modules.misconfig import MisconfigModule
from modules.bola import BolaModule
from modules.broken_auth import BrokenAuthModule
from modules.mass_assignment import MassAssignmentModule
from modules.bfla import BflaModule
from modules.ssrf import SsrfModule
from modules.sqli import SqliModule
from modules.extras import (
    NoSqliModule, CmdiModule, XssModule,
    RateLimitModule, CorsModule, JwtAttacksModule,
    InventoryModule, InputFuzzingModule,
)

ALL_MODULES: list[type[BaseModule]] = [
    MisconfigModule,
    BolaModule,
    BrokenAuthModule,
    MassAssignmentModule,
    BflaModule,
    SsrfModule,
    SqliModule,
    NoSqliModule,
    CmdiModule,
    XssModule,
    RateLimitModule,
    CorsModule,
    JwtAttacksModule,
    InventoryModule,
    InputFuzzingModule,
]

MODULE_REGISTRY: dict[str, type[BaseModule]] = {
    cls.name: cls for cls in ALL_MODULES
}


def get_module_instances(enabled_names: list[str] | None = None) -> list[BaseModule]:
    """Return instantiated modules, optionally filtered by name."""
    if not enabled_names:
        return [cls() for cls in ALL_MODULES]
    return [cls() for cls in ALL_MODULES if cls.name in enabled_names]


def get_module_info() -> list[dict]:
    """Return a list of module metadata for the frontend."""
    return [
        {
            "name": cls.name,
            "title": cls.title,
            "owasp_category": cls.owasp_category,
            "cwe_ids": cls.cwe_ids,
            "severity_default": cls.severity_default,
            "safe_mode_compatible": cls.safe_mode_compatible,
            "destructive": cls.destructive,
        }
        for cls in ALL_MODULES
    ]
