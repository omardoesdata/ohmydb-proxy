"""Read-only MySQL/MariaDB impact estimator."""

from __future__ import annotations

import asyncio

import aiomysql

from sql_safety_proxy.risk_estimator import DbConnectionOptions


async def estimate_mysql_rows(
    preview_query: str,
    options: DbConnectionOptions,
) -> int:
    connection = await asyncio.wait_for(
        aiomysql.connect(
            host=options.host,
            port=options.port,
            user=options.user,
            password=options.password,
            db=options.database,
            autocommit=False,
            connect_timeout=options.timeout_seconds,
        ),
        timeout=options.timeout_seconds,
    )

    try:
        async with connection.cursor() as cursor:
            await cursor.execute("SET TRANSACTION READ ONLY")
            await cursor.execute("START TRANSACTION")
            await asyncio.wait_for(
                cursor.execute(preview_query),
                timeout=options.timeout_seconds,
            )
            row = await cursor.fetchone()
            await connection.rollback()
            return int(row[0] if row else 0)
    finally:
        connection.close()
