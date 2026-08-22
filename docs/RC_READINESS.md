# v0.9.0rc1 Release Readiness

## Purpose

v0.9.0rc1 is the release-candidate hardening milestone for SQL Safety Proxy.
No broad new database features are being added in this release.

## Validated scope

- PostgreSQL real runtime validation
- psycopg simple-query path
- psycopg extended protocol
- asyncpg extended protocol
- prepared-statement handling
- transaction-state handling
- transaction recovery
- fail-closed dangerous mutation handling
- structural statement blocking
- multi-statement blocking
- audit and integrity validation
- security and sanitization hardening
- fresh-wheel installation
- Docker runtime
- CLI/configuration behavior
- package build and metadata validation
- repeatable PostgreSQL latency baseline

## Current RC regression checkpoint

- full pytest suite: 341 passed
- compileall: passed
- pip dependency check: passed
- git diff check: passed
- real PostgreSQL integration matrix: passed

## Performance baseline

- workload: SELECT 1
- warm-up iterations: 20
- measured iterations: 200
- direct PostgreSQL mean: 1.537 ms
- proxy mean: 2.588 ms
- measured mean proxy overhead: 1.051 ms
- direct p95: 2.127 ms
- proxy p95: 3.183 ms

These numbers are a local development baseline and are not production guarantees.

## Deferred / known limitations

- MariaDB Connector/Python native Windows integration remains deferred.
- TLS termination is not a fully validated supported capability.
- ambiguous or unsupported prepared parameter forms intentionally fail closed.
- performance varies by hardware, workload, network topology, and policy configuration.

## Release candidate principle

Unknown, malformed, ambiguous, or unsupported database behavior must continue to fail safely rather than bypass SQL Safety Proxy policy enforcement.
