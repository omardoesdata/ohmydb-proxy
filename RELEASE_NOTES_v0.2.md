# v0.2.0

## Fixed

- Full-table `UPDATE` and `DELETE` statements now receive a real row-count
  preview instead of always showing `Estimated rows affected: unavailable`.
- `TRUNCATE TABLE` also attempts a full-table count before confirmation.
- Preview execution now uses a read-only PostgreSQL transaction and a bounded
  timeout.

## Architecture

- Added an `ImpactEstimator` interface and PostgreSQL adapter registry.
- Added `DATABASE_ENGINE` and `ESTIMATE_TIMEOUT_SECONDS` settings.
- Documented the protocol-plus-estimator adapter strategy for multi-database
  support.

## Important scope note

The network proxy is currently PostgreSQL-specific. The shared classifier and
popup are dialect-aware, but true MySQL, SQL Server, Oracle, and SQLite support
requires their respective interception adapters.
