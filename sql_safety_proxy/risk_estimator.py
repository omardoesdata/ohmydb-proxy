"""Database impact-estimation adapters.

The proxy protocol and the estimator are intentionally separate. PostgreSQL is
the first implemented adapter; MySQL, SQL Server, SQLite and others can add an
adapter implementing the same small interface without changing classification
or confirmation UI code.
"""
from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass

import asyncpg


@dataclass(frozen=True)
class DbConnectionOptions:
    host: str
    port: int
    user: str
    password: str
    database: str
    timeout_seconds: float = 8.0


class ImpactEstimator(ABC):
    @abstractmethod
    async def estimate_rows(self, preview_query: str, opts: DbConnectionOptions) -> int:
        raise NotImplementedError


class PostgresImpactEstimator(ImpactEstimator):
    async def estimate_rows(self, preview_query: str, opts: DbConnectionOptions) -> int:
        conn = await asyncpg.connect(
            host=opts.host,
            port=opts.port,
            user=opts.user,
            password=opts.password,
            database=opts.database,
            timeout=opts.timeout_seconds,
            command_timeout=opts.timeout_seconds,
        )
        try:
            # Defense in depth: the preview session itself is read-only.
            async with conn.transaction(readonly=True):
                value = await asyncio.wait_for(
                    conn.fetchval(preview_query),
                    timeout=opts.timeout_seconds,
                )
            return int(value or 0)
        finally:
            await conn.close()


_ESTIMATORS: dict[str, ImpactEstimator] = {
    "postgres": PostgresImpactEstimator(),
    "postgresql": PostgresImpactEstimator(),
}


def get_estimator(engine: str) -> ImpactEstimator:
    key = engine.strip().lower()
    try:
        return _ESTIMATORS[key]
    except KeyError as exc:
        supported = ", ".join(sorted(_ESTIMATORS))
        raise ValueError(
            f"No impact estimator adapter for {engine!r}. Currently available: {supported}"
        ) from exc


async def estimate_affected_rows(
    preview_query: str,
    opts: DbConnectionOptions,
    engine: str = "postgres",
) -> int:
    return await get_estimator(engine).estimate_rows(preview_query, opts)
