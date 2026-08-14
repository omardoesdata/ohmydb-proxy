"""Minimal psycopg example for SQL Safety Proxy.

Run only against a disposable development database.
The connection must point to the proxy port, not directly to PostgreSQL.
"""

import os
import sys

import psycopg


def required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} must be set")
    return value


def main() -> int:
    dangerous_demo = "--dangerous-demo" in sys.argv

    sql = (
        "UPDATE sql_safety_demo SET active = FALSE;"
        if dangerous_demo
        else "SELECT 1 AS proxy_check;"
    )

    with psycopg.connect(
        host=os.getenv("PGHOST", "127.0.0.1"),
        port=int(os.getenv("PGPORT", "5433")),
        user=required_env("PGUSER"),
        password=required_env("PGPASSWORD"),
        dbname=required_env("PGDATABASE"),
    ) as conn:
        try:
            with conn.cursor() as cur:
                cur.execute(sql)

                if cur.description:
                    print(cur.fetchall())
                else:
                    print("Statement completed.")
        except Exception as exc:
            print(f"Proxy/database response: {exc}")
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())