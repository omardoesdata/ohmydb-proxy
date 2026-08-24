"""Minimal mysql-connector-python example for OhMyDB.

Run only against a disposable development database.
The connection must point to the proxy port, not directly to MySQL/MariaDB.
"""

import os
import sys

import mysql.connector


def required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} must be set")
    return value


def main() -> int:
    dangerous_demo = "--dangerous-demo" in sys.argv

    sql = (
        "UPDATE sql_safety_demo SET active = 0;"
        if dangerous_demo
        else "SELECT 1 AS proxy_check;"
    )

    conn = mysql.connector.connect(
        host=os.getenv("MYSQL_HOST", "127.0.0.1"),
        port=int(os.getenv("MYSQL_PORT", "3307")),
        user=required_env("MYSQL_USER"),
        password=required_env("MYSQL_PASSWORD"),
        database=required_env("MYSQL_DATABASE"),
        ssl_disabled=True,
    )

    try:
        cursor = conn.cursor()

        try:
            cursor.execute(sql)

            if cursor.with_rows:
                print(cursor.fetchall())
            else:
                conn.commit()
                print("Statement completed.")
        except Exception as exc:
            conn.rollback()
            print(f"Proxy/database response: {exc}")
            return 1
        finally:
            cursor.close()
    finally:
        conn.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())