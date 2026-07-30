"""Real PostgreSQL integration matrix for v0.5."""

from __future__ import annotations

import asyncio
import json
import socket
import time
from contextlib import closing, suppress
from pathlib import Path

import asyncpg
import psycopg
from psycopg import ClientCursor

from sql_safety_proxy.adapters.registry import get_adapter
from sql_safety_proxy.audit import JsonlAuditLogger
from sql_safety_proxy.confirmation import AutoDenyProvider
from sql_safety_proxy.policy import PolicyAction, PolicyConfig
from sql_safety_proxy.proxy import (
    ProxyOptions,
    start_intercepting_proxy,
)

HOST = "127.0.0.1"
DB_PORT = 5432
PROXY_PORT = 5433
DATABASE = "sql_safety_v05"
APP_USER = "proxy_app"
APP_PASSWORD = "proxy_app_local"
ESTIMATOR_USER = "proxy_estimator"
ESTIMATOR_PASSWORD = "proxy_estimator_local"
AUDIT_PATH = Path("logs/v05-integration-audit.jsonl")


def wait_for_proxy() -> None:
    deadline = time.monotonic() + 10

    while time.monotonic() < deadline:
        with closing(socket.socket()) as sock:
            if sock.connect_ex((HOST, PROXY_PORT)) == 0:
                return
        time.sleep(0.1)

    raise RuntimeError("Proxy did not start on port 5433")


def connect(
    port: int,
    *,
    simple: bool = False,
    autocommit: bool = True,
):
    arguments = {
        "host": HOST,
        "port": port,
        "dbname": DATABASE,
        "user": APP_USER,
        "password": APP_PASSWORD,
        "sslmode": "disable",
        "autocommit": autocommit,
    }

    if simple:
        arguments["cursor_factory"] = ClientCursor

    return psycopg.connect(**arguments)


def scalar(sql: str):
    with connect(DB_PORT) as connection:
        return connection.execute(sql).fetchone()[0]


def reset_fixture() -> None:
    with connect(DB_PORT) as connection:
        connection.execute(
            "UPDATE safety_users SET active = true"
        )


def expect_blocked(label: str, operation) -> None:
    try:
        operation()
    except Exception as exc:
        assert (
            "blocked by sql-safety-proxy"
            in str(exc).lower()
        ), (label, exc)

        print(f"PASS blocked: {label}")
        return

    raise AssertionError(
        f"{label}: query unexpectedly reached PostgreSQL"
    )


async def run_asyncpg_checks() -> None:
    connection = await asyncpg.connect(
        host=HOST,
        port=PROXY_PORT,
        database=DATABASE,
        user=APP_USER,
        password=APP_PASSWORD,
        ssl=False,
    )

    try:
        assert (
            await connection.fetchval(
                "SELECT COUNT(*) FROM safety_users"
            )
            == 50
        )

        result = await connection.execute(
            "UPDATE safety_users "
            "SET active = false WHERE id = $1",
            2,
        )
        assert result == "UPDATE 1"

        try:
            await connection.execute(
                "DELETE FROM safety_users"
            )
        except Exception as exc:
            assert (
                "blocked by sql-safety-proxy"
                in str(exc).lower()
            )
        else:
            raise AssertionError(
                "asyncpg full-table DELETE was not blocked"
            )

        assert (
            await connection.fetchval(
                "SELECT COUNT(*) FROM safety_users"
            )
            == 50
        )

        print("PASS asyncpg extended protocol and recovery")
    finally:
        await connection.close()


async def main() -> None:
    adapter = get_adapter("postgres")
    assert adapter.capabilities.transaction_state

    reset_fixture()

    AUDIT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    AUDIT_PATH.unlink(missing_ok=True)

    options = ProxyOptions(
        listen_port=PROXY_PORT,
        target_host=HOST,
        target_port=DB_PORT,
        dialect=adapter.dialect,
        estimator_user=ESTIMATOR_USER,
        estimator_password=ESTIMATOR_PASSWORD,
        confirmation_provider=AutoDenyProvider(),
        database_engine=adapter.name,
        adapter_name=adapter.name,
        estimate_timeout_seconds=5,
        policy_config=PolicyConfig(
            auto_allow_max_rows=3,
            block_at_rows=20,
            no_where_action=PolicyAction.BLOCK,
            structural_action=PolicyAction.BLOCK,
            unknown_action=PolicyAction.BLOCK,
            estimation_failure_action=PolicyAction.BLOCK,
            multi_statement_action=PolicyAction.BLOCK,
        ),
        audit_logger=JsonlAuditLogger(AUDIT_PATH),
    )

    proxy_task = asyncio.create_task(
        start_intercepting_proxy(options)
    )

    await asyncio.to_thread(wait_for_proxy)

    try:
        def simple_query_matrix() -> None:
            with connect(
                PROXY_PORT,
                simple=True,
            ) as connection:
                assert (
                    connection.execute(
                        "SELECT COUNT(*) FROM safety_users"
                    ).fetchone()[0]
                    == 50
                )

                connection.execute(
                    "UPDATE safety_users "
                    "SET active = false WHERE id = 1"
                )

                assert (
                    scalar(
                        "SELECT active FROM safety_users "
                        "WHERE id = 1"
                    )
                    is False
                )

                before = scalar(
                    "SELECT COUNT(*) FROM safety_users "
                    "WHERE active"
                )

                expect_blocked(
                    "full-table UPDATE",
                    lambda: connection.execute(
                        "UPDATE safety_users "
                        "SET active = false"
                    ),
                )

                assert (
                    scalar(
                        "SELECT COUNT(*) FROM safety_users "
                        "WHERE active"
                    )
                    == before
                )

                expect_blocked(
                    "multi-statement batch",
                    lambda: connection.execute(
                        "SELECT 1; DELETE FROM safety_users"
                    ),
                )

                expect_blocked(
                    "structural CREATE",
                    lambda: connection.execute(
                        "CREATE TABLE v05_should_not_exist"
                        "(id integer)"
                    ),
                )

                assert (
                    scalar(
                        "SELECT "
                        "to_regclass('public.v05_should_not_exist') "
                        "IS NULL"
                    )
                    is True
                )

                print("PASS psycopg Simple Query matrix")

        await asyncio.to_thread(simple_query_matrix)

        def psycopg_extended_matrix() -> None:
            with connect(PROXY_PORT) as connection:
                connection.execute(
                    "UPDATE safety_users "
                    "SET active = false WHERE id = %s",
                    (3,),
                )

                assert (
                    scalar(
                        "SELECT active FROM safety_users "
                        "WHERE id = 3"
                    )
                    is False
                )

                print("PASS psycopg extended protocol")

        await asyncio.to_thread(
            psycopg_extended_matrix
        )

        await run_asyncpg_checks()

        def transaction_matrix() -> None:
            with connect(
                PROXY_PORT,
                simple=True,
                autocommit=False,
            ) as connection:
                cursor = connection.cursor()

                assert (
                    cursor.execute(
                        "SELECT 1"
                    ).fetchone()[0]
                    == 1
                )

                expect_blocked(
                    "blocked UPDATE inside transaction",
                    lambda: cursor.execute(
                        "UPDATE safety_users "
                        "SET active = false"
                    ),
                )

                assert (
                    cursor.execute(
                        "SELECT 2"
                    ).fetchone()[0]
                    == 2
                )

                connection.rollback()
                print("PASS transaction recovery")

        await asyncio.to_thread(transaction_matrix)

        events = [
            json.loads(line)
            for line in AUDIT_PATH.read_text(
                encoding="utf-8"
            ).splitlines()
            if line.strip()
        ]

        assert len(events) >= 7

        assert {"simple", "extended"} <= {
            event["protocol"]
            for event in events
        }

        assert {
            "UPDATE",
            "DELETE",
            "MULTI_STATEMENT",
            "CREATE",
        } <= {
            event["operation"]
            for event in events
        }

        assert (
            scalar(
                "SELECT COUNT(*) FROM safety_users"
            )
            == 50
        )

        assert (
            scalar(
                "SELECT COUNT(*) FROM safety_orders"
            )
            == 200
        )

        print(
            f"PASS audit and integrity "
            f"({len(events)} events)"
        )
    finally:
        proxy_task.cancel()

        with suppress(asyncio.CancelledError):
            await proxy_task

        reset_fixture()

    print(
        "\nV0.5 REAL POSTGRESQL "
        "INTEGRATION MATRIX PASSED"
    )


if __name__ == "__main__":
    asyncio.run(main())