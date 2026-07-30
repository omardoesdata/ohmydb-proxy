"""Database adapter framework."""

from .base import DatabaseAdapter, DatabaseCapabilities
from .registry import get_adapter, list_adapters, register_adapter, resolve_adapter_name

__all__ = [
    "DatabaseAdapter",
    "DatabaseCapabilities",
    "get_adapter",
    "list_adapters",
    "register_adapter",
    "resolve_adapter_name",
]