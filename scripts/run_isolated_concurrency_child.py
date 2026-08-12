"""Run one real-database concurrency matrix in a connector-isolated process."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import importlib
import io
import json
import os
import socket
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from sql_safety_proxy.audit import JsonlAuditLogger
from sql_safety_proxy.confirmation import AutoDenyProvider
from sql_safety_proxy.fail_safe import FailSafeMode
from sql_safety_proxy.policy import PolicyAction, PolicyConfig
from sql_safety_proxy.proxy import ProxyOptions, start_intercepting_proxy


HOST = os.environ.get("SQL_SAFETY_INTEGRATION_HOST", "127.0.0.1")
SECRET_SENTINEL = "SQL_SAFETY_CONCURRENCY_SECRET_SENTINEL"
WINDOWS_MARIADB_LIMITATION = (
    "SKIPPED - MariaDB Connector/Python native runtime validation is "
    "disabled on Windows; Linux validation is required before RC"
)


def setting(name: str, default: str) -> str:
    return os.environ.get(name, default)


def required_setting(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"required environment variable is unset: {name}")
    return value


def policy() -> PolicyConfig:
    return PolicyConfig(
        auto_allow_max_rows=1,
        block_at_rows=5,
        no_where_action=PolicyAction.BLOCK,
        structural_action=PolicyAction.BLOCK,
        unknown_action=PolicyAction.BLOCK,
        estimation_failure_action=PolicyAction.BLOCK,
        multi_statement_action=PolicyAction.BLOCK,
    )


def options(connector: str, listen_port: int, audit_path: Path) -> ProxyOptions:
    postgres = connector == "postgres"
    prefix = "PG" if postgres else "MYSQL"
    backend_port = int(setting(f"SQL_SAFETY_{prefix}_PORT", "5432" if postgres else "13306"))
    database = setting(
        f"SQL_SAFETY_{prefix}_DATABASE",
        "sql_safety_v05" if postgres else "sql_safety_rc",
    )
    return ProxyOptions(
        listen_port=listen_port,
        target_host=HOST,
        target_port=backend_port,
        dialect="postgres" if postgres else "mysql",
        estimator_user=setting(f"SQL_SAFETY_{prefix}_ESTIMATOR_USER", "proxy_estimator"),
        estimator_password=required_setting(
            f"SQL_SAFETY_{prefix}_ESTIMATOR_PASSWORD"
        ),
        confirmation_provider=AutoDenyProvider(),
        database_engine="postgres" if postgres else "mysql",
        adapter_name="postgres" if postgres else "mysql",
        database_name=database,
        estimate_timeout_seconds=3,
        backend_connect_timeout_seconds=3,
        socket_read_timeout_seconds=5,
        policy_config=policy(),
        fail_safe_mode=FailSafeMode.BALANCED,
        audit_logger=JsonlAuditLogger(audit_path),
    )


async def wait_port(port: int) -> None:
    deadline = asyncio.get_running_loop().time() + 10
    while asyncio.get_running_loop().time() < deadline:
        try:
            reader, writer = await asyncio.open_connection(HOST, port)
            del reader
            writer.close()
            await writer.wait_closed()
            return
        except OSError:
            await asyncio.sleep(0.05)
    raise RuntimeError(f"listener {port} did not start")


def load_connector(name: str) -> Any:
    # This function is the isolation boundary: a child imports exactly one driver.
    module_name = {
        "postgres": "psycopg",
        "mysql-connector-python": "mysql.connector",
        "mariadb": "mariadb",
    }[name]
    return importlib.import_module(module_name)


class Matrix:
    def __init__(self, connector: str, driver: Any, proxy_port: int) -> None:
        self.connector = connector
        self.driver = driver
        self.proxy_port = proxy_port
        self.postgres = connector == "postgres"
        self.prefix = "PG" if self.postgres else "MYSQL"
        self.backend_port = int(
            setting(f"SQL_SAFETY_{self.prefix}_PORT", "5432" if self.postgres else "13306")
        )
        self.database = setting(
            f"SQL_SAFETY_{self.prefix}_DATABASE",
            "sql_safety_v05" if self.postgres else "sql_safety_rc",
        )
        self.app_user = setting(f"SQL_SAFETY_{self.prefix}_APP_USER", "proxy_app")
        self.app_password = required_setting(
            f"SQL_SAFETY_{self.prefix}_APP_PASSWORD"
        )
        self.row_ids = {
            "postgres": (1, 2),
            "mysql-connector-python": (3, 5),
            "mariadb": (4, 6),
        }[connector]

    def connect(self, *, proxy: bool = True, autocommit: bool = True):
        port = self.proxy_port if proxy else self.backend_port
        if self.postgres:
            return self.driver.connect(
                host=HOST,
                port=port,
                dbname=self.database,
                user=self.app_user,
                password=self.app_password,
                sslmode="disable",
                autocommit=autocommit,
                connect_timeout=3,
            )
        arguments = {
            "host": HOST,
            "port": port,
            "user": self.app_user,
            "password": self.app_password,
            "database": self.database,
            "autocommit": autocommit,
        }
        if self.connector == "mysql-connector-python":
            arguments.update(ssl_disabled=True, connection_timeout=3)
        else:
            arguments.update(connect_timeout=3)
        return self.driver.connect(**arguments)

    def scalar(self, sql: str, params: tuple[Any, ...] = ()) -> Any:
        connection = self.connect()
        try:
            if self.postgres:
                return connection.execute(sql, params).fetchone()[0]
            cursor = connection.cursor()
            try:
                cursor.execute(sql, params)
                return cursor.fetchone()[0]
            finally:
                cursor.close()
        finally:
            connection.close()

    def expect_block(self) -> None:
        connection = self.connect()
        try:
            try:
                if self.postgres:
                    connection.execute("UPDATE safety_users SET active = false")
                else:
                    cursor = connection.cursor()
                    try:
                        cursor.execute("UPDATE safety_users SET active = false")
                    finally:
                        cursor.close()
            except Exception as exc:
                messages = []
                current: BaseException | None = exc
                while current is not None:
                    messages.append(str(current))
                    current = current.__cause__
                if "blocked by sql-safety-proxy" not in " ".join(messages).lower():
                    raise AssertionError("unsafe query failed for an unexpected reason") from exc
                return
            raise AssertionError("unsafe query was forwarded")
        finally:
            connection.close()

    def safe(self, index: int) -> int:
        placeholder = "%s" if self.connector != "mariadb" else "?"
        return int(
            self.scalar(
                f"SELECT id FROM safety_users WHERE id = {placeholder}",
                ((index % 8) + 1,),
            )
        )

    def transaction(self, row_id: int, commit: bool) -> None:
        connection = self.connect(autocommit=False)
        try:
            placeholder = "%s" if self.connector != "mariadb" else "?"
            if self.postgres:
                connection.execute(
                    f"UPDATE safety_users SET active = false WHERE id = {placeholder}",
                    (row_id,),
                )
                connection.execute(f"SELECT {placeholder}", (SECRET_SENTINEL,)).fetchone()
            else:
                cursor = connection.cursor(prepared=True)
                try:
                    cursor.execute(
                        f"UPDATE safety_users SET active = {placeholder} WHERE id = {placeholder}",
                        (0, row_id),
                    )
                    cursor.execute(f"SELECT {placeholder}", (SECRET_SENTINEL,))
                    assert cursor.fetchone()[0] == SECRET_SENTINEL
                finally:
                    cursor.close()
            connection.commit() if commit else connection.rollback()
        finally:
            connection.close()

    def reset_rows(self) -> None:
        connection = self.connect(proxy=False)
        try:
            placeholders = "%s, %s" if self.connector != "mariadb" else "?, ?"
            if self.postgres:
                connection.execute(
                    f"UPDATE safety_users SET active = true WHERE id IN ({placeholders})",
                    self.row_ids,
                )
            else:
                cursor = connection.cursor()
                try:
                    cursor.execute(
                        f"UPDATE safety_users SET active = 1 WHERE id IN ({placeholders})",
                        self.row_ids,
                    )
                finally:
                    cursor.close()
        finally:
            connection.close()

    def run_concurrent(self) -> dict[str, int]:
        self.reset_rows()
        with ThreadPoolExecutor(max_workers=12) as pool:
            values = list(pool.map(self.safe, range(24)))
            mixed = [
                pool.submit(self.safe, index) if index % 2 else pool.submit(self.expect_block)
                for index in range(10)
            ]
            for future in mixed:
                future.result()

        rollback_id, commit_id = self.row_ids
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(self.transaction, rollback_id, False),
                pool.submit(self.transaction, commit_id, True),
            ]
            for future in futures:
                future.result()
        assert bool(self.scalar(f"SELECT active FROM safety_users WHERE id = {rollback_id}"))
        assert not bool(self.scalar(f"SELECT active FROM safety_users WHERE id = {commit_id}"))

        anchor = self.connect()
        transient = self.connect()
        transient.close()
        try:
            if self.postgres:
                assert anchor.execute("SELECT 13").fetchone()[0] == 13
            else:
                cursor = anchor.cursor()
                try:
                    cursor.execute("SELECT 13")
                    assert cursor.fetchone()[0] == 13
                finally:
                    cursor.close()
            for _ in range(10):
                assert self.scalar("SELECT 1") == 1
        finally:
            anchor.close()

        with socket.create_connection((HOST, self.proxy_port), timeout=2):
            pass
        assert self.scalar("SELECT 14") == 14
        return {"safe_clients": len(values), "mixed_operations": len(mixed)}

async def assert_shutdown_closes_client(matrix: Matrix, proxy_task: asyncio.Task[Any]) -> None:
    connection = await asyncio.to_thread(matrix.connect)
    proxy_task.cancel()
    await asyncio.gather(proxy_task, return_exceptions=True)
    try:
        if matrix.postgres:
            connection.execute("SELECT 1")
        else:
            cursor = connection.cursor()
            try:
                cursor.execute("SELECT 1")
            finally:
                cursor.close()
    except Exception:
        return
    finally:
        with contextlib.suppress(Exception):
            connection.close()
    raise AssertionError("connected client survived proxy shutdown")


async def run_child(
    connector: str,
    proxy_port: int,
    audit_path: Path,
) -> dict[str, Any]:
    driver = load_connector(connector)
    matrix = Matrix(connector, driver, proxy_port)
    audit_path.unlink(missing_ok=True)
    proxy_task: asyncio.Task[Any] | None = None
    captured = io.StringIO()
    try:
        with contextlib.redirect_stdout(captured):
            proxy_task = asyncio.create_task(
                start_intercepting_proxy(options(connector, proxy_port, audit_path))
            )
            await wait_port(proxy_port)
            result = await asyncio.to_thread(matrix.run_concurrent)
        content = audit_path.read_text(encoding="utf-8")
        assert SECRET_SENTINEL not in content
        for line in content.splitlines():
            json.loads(line)
        with contextlib.redirect_stdout(captured):
            await assert_shutdown_closes_client(matrix, proxy_task)
        proxy_task = None
        return {
            "connector": connector,
            "workload": "concurrent",
            "status": "passed",
            "exit_code": 0,
            "matrix": result,
            "cleanup": "passed",
            "secret_leak": "not found",
        }
    finally:
        if proxy_task is not None:
            proxy_task.cancel()
            await asyncio.gather(proxy_task, return_exceptions=True)
        with contextlib.suppress(Exception):
            await asyncio.to_thread(matrix.reset_rows)
        audit_path.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "connector",
        choices=("postgres", "mysql-connector-python", "mariadb"),
    )
    parser.add_argument("--proxy-port", type=int)
    parser.add_argument("--work-dir", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if (
        sys.platform == "win32"
        and args.connector == "mariadb"
    ):
        print(
            json.dumps(
                {
                    "connector": args.connector,
                    "workload": "concurrent",
                    "status": "skipped",
                    "exit_code": 0,
                    "reason": WINDOWS_MARIADB_LIMITATION,
                },
                sort_keys=True,
            )
        )
        return 0

    default_ports = {
        "postgres": 15433,
        "mysql-connector-python": 13308,
        "mariadb": 13309,
    }
    proxy_port = args.proxy_port or default_ports[args.connector]
    temporary = None
    if args.work_dir is None:
        temporary = tempfile.TemporaryDirectory(prefix="sql-safety-concurrency-")
        work_dir = Path(temporary.name)
    else:
        work_dir = args.work_dir
        work_dir.mkdir(parents=True, exist_ok=True)
    try:
        result = asyncio.run(
            run_child(
                args.connector,
                proxy_port,
                work_dir / "audit.jsonl",
            )
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except BaseException as exc:
        # Deliberately avoid exception text: database drivers may echo connection data.
        print(
            json.dumps(
                {
                    "connector": args.connector,
                    "workload": "concurrent",
                    "status": "failed",
                    "exit_code": 1,
                    "error_type": type(exc).__name__,
                },
                sort_keys=True,
            )
        )
        return 1
    finally:
        if temporary is not None:
            temporary.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
