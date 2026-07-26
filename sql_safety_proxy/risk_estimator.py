"""Runs a read-only preview query (e.g. SELECT COUNT(*) FROM ... WHERE ...)
against the real database on a SEPARATE connection, so we never touch the
client's in-flight session state.
"""
from dataclasses import dataclass

import asyncpg


@dataclass
class DbConnectionOptions:
    host: str
    port: int
    user: str
    password: str
    database: str


async def estimate_affected_rows(preview_query: str, opts: DbConnectionOptions) -> int:
    conn = await asyncpg.connect(
        host=opts.host, port=opts.port, user=opts.user,
        password=opts.password, database=opts.database,
    )
    try:
        return await conn.fetchval(preview_query)
    finally:
        await conn.close()
