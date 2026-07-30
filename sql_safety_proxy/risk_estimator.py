"""Database-independent impact-estimation entry points."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DbConnectionOptions:
    host: str
    port: int
    user: str
    password: str
    database: str
    timeout_seconds: float = 8.0


async def estimate_affected_rows(
    preview_query: str,
    opts: DbConnectionOptions,
    engine: str = "postgres",
) -> int:
    from .adapters.registry import get_adapter

    return await get_adapter(engine).estimate_rows(
        preview_query,
        opts,
    )


def get_estimator(engine: str):
    from .adapters.registry import get_adapter

    return get_adapter(engine)