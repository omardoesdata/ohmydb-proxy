"""Aggregate real concurrency checks without co-loading native DB connectors."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CHILD = ROOT / "scripts" / "run_isolated_concurrency_child.py"
CONCURRENT_CHILDREN = {
    "postgres": 15433,
    "mysql-connector-python": 13308,
}
MARIADB_PORT = 13309
WINDOWS_MARIADB_LIMITATION = (
    "SKIPPED - MariaDB Connector/Python native runtime validation is "
    "disabled on Windows; Linux validation is required before RC"
)


def run_child(
    connector: str,
    port: int,
    work_dir: Path,
) -> dict[str, Any]:
    completed = subprocess.run(
        [
            sys.executable,
            str(CHILD),
            connector,
            "--proxy-port",
            str(port),
            "--work-dir",
            str(work_dir / connector),
        ],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    try:
        result = json.loads(lines[-1])
    except (IndexError, json.JSONDecodeError):
        result = {
            "connector": connector,
            "status": "failed",
            "error_type": "MissingChildResult",
        }
    result["exit_code"] = completed.returncode
    if completed.returncode != 0:
        result["status"] = "failed"
    return result


def run_child_safely(
    connector: str,
    port: int,
    work_dir: Path,
) -> dict[str, Any]:
    try:
        return run_child(connector, port, work_dir)
    except subprocess.TimeoutExpired:
        return {
            "connector": connector,
            "workload": "concurrent",
            "status": "failed",
            "exit_code": 124,
            "error_type": "TimeoutExpired",
        }


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="sql-safety-concurrency-") as temp:
        work_dir = Path(temp)
        results: dict[str, dict[str, Any]] = {}
        with ThreadPoolExecutor(max_workers=len(CONCURRENT_CHILDREN)) as pool:
            futures = {
                pool.submit(
                    run_child_safely,
                    connector,
                    port,
                    work_dir,
                ): connector
                for connector, port in CONCURRENT_CHILDREN.items()
            }
            for future in as_completed(futures):
                connector = futures[future]
                results[connector] = future.result()

        if sys.platform == "win32":
            results["mariadb-connector-python"] = {
                "connector": "mariadb",
                "workload": "concurrent",
                "status": "skipped",
                "exit_code": 0,
                "reason": WINDOWS_MARIADB_LIMITATION,
            }
        else:
            results["mariadb-connector-python"] = run_child_safely(
                "mariadb",
                MARIADB_PORT,
                work_dir / "mariadb-connector-python",
            )

    order = (*CONCURRENT_CHILDREN, "mariadb-connector-python")
    ordered = {name: results[name] for name in order}
    passed = all(
        result.get("status") in {"passed", "skipped"}
        and result.get("exit_code") == 0
        for result in ordered.values()
    )
    print(
        json.dumps(
            {
                "status": "passed" if passed else "failed",
                "children": ordered,
            },
            sort_keys=True,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
