"""Minimal asyncpg example for SQL Safety Proxy.

Run only against a disposable development database.
The connection must point to the proxy port, not directly to PostgreSQL.
"""

import asyncio
import os
import sys

import asyncpg


def required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} must be set")
    return value


async def run() -> int:
    dangerous_demo = "--dangerous-demo" in sys.argv

    sql = (
        "UPDATE sql_safety_demo SET active = FALSE;"
        if dangerous_demo
        else "SELECT 1 AS proxy_check;"
    )

    conn = await asyncpg.connect(
        host=os.getenv("PGHOST", "127.0.0.1"),
        port=int(os.getenv("PGPORT", "5433")),
        user=required_env("PGUSER"),
        password=required_env("PGPASSWORD"),
        database=required_env("PGDATABASE"),
    )

    try:
        if dangerous_demo:
            result = await conn.execute(sql)
            print(result)
        else:
            rows = await conn.fetch(sql)
            print(rows)
    except Exception as exc:
        print(f"Proxy/database response: {exc}")
        return 1
    finally:
        await conn.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))