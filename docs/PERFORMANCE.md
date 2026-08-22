# Performance Baseline

## v0.9.0rc1 local PostgreSQL baseline

The first repeatable SQL Safety Proxy latency baseline was captured during v0.9 RC hardening.

Environment:

- PostgreSQL 16 running locally in Docker
- backend: 127.0.0.1:5432
- proxy: 127.0.0.1:5433
- workload: SELECT 1
- warm-up: 20 iterations
- measured iterations: 200

Results:

| Metric | Direct PostgreSQL | Through Proxy | Proxy Overhead |
| --- | ---: | ---: | ---: |
| Mean | 1.537 ms | 2.588 ms | 1.051 ms |
| p50 | 1.448 ms | 2.550 ms | 1.103 ms |
| p95 | 2.127 ms | 3.183 ms | 1.056 ms |

This is a local development baseline, not a production throughput or latency guarantee.
Results can vary by hardware, operating system, database configuration, workload, network topology, and policy configuration.

The repeatable benchmark is available at `scripts/run_v09_benchmark.py`.
