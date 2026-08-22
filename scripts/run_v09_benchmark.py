"""Repeatable PostgreSQL latency benchmark for v0.9 RC."""

from __future__ import annotations

import json
import os
import statistics
import time
from pathlib import Path

import psycopg

HOST = "127.0.0.1"
DIRECT_PORT = 5432
PROXY_PORT = 5433
DATABASE = "sql_safety_v05"
USER = "proxy_app"
PASSWORD = os.getenv("V09_BENCH_PASSWORD")
ITERATIONS = 200
WARMUP = 20
RESULT_PATH = Path("artifacts/v09-postgres-benchmark.json")


def connect(port: int):
    if not PASSWORD:
        raise RuntimeError("V09_BENCH_PASSWORD must be set")
    return psycopg.connect(
        host=HOST,
        port=port,
        dbname=DATABASE,
        user=USER,
        password=PASSWORD,
        sslmode="disable",
        autocommit=True,
    )


def percentile(values: list[float], percentile_value: float) -> float:
    ordered = sorted(values)
    index = round((len(ordered) - 1) * percentile_value)
    return ordered[index]


def measure(port: int) -> dict[str, float]:
    samples: list[float] = []

    with connect(port) as connection:
        for _ in range(WARMUP):
            connection.execute("SELECT 1").fetchone()

        for _ in range(ITERATIONS):
            started = time.perf_counter_ns()
            row = connection.execute("SELECT 1").fetchone()
            elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000

            assert row == (1,)
            samples.append(elapsed_ms)

    return {
        "iterations": ITERATIONS,
        "mean_ms": statistics.fmean(samples),
        "p50_ms": percentile(samples, 0.50),
        "p95_ms": percentile(samples, 0.95),
        "min_ms": min(samples),
        "max_ms": max(samples),
    }


def main() -> None:
    direct = measure(DIRECT_PORT)
    proxy = measure(PROXY_PORT)

    overhead = {
        "mean_ms": proxy["mean_ms"] - direct["mean_ms"],
        "p50_ms": proxy["p50_ms"] - direct["p50_ms"],
        "p95_ms": proxy["p95_ms"] - direct["p95_ms"],
    }

    result = {
        "benchmark": "postgres-select-1-latency",
        "host": HOST,
        "database": DATABASE,
        "direct_port": DIRECT_PORT,
        "proxy_port": PROXY_PORT,
        "warmup_iterations": WARMUP,
        "direct": direct,
        "proxy": proxy,
        "proxy_overhead": overhead,
    }

    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULT_PATH.write_text(
        json.dumps(result, indent=2) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(result, indent=2))
    print(f"Saved benchmark to {RESULT_PATH}")


if __name__ == "__main__":
    main()
