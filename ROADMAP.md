# Roadmap

## v0.2 — PostgreSQL safety hardening

- estimate full-table `UPDATE`, `DELETE`, and `TRUNCATE`
- fail closed for unknown execution states
- parameter type OID tracking
- transaction-aware blocking behavior
- multi-statement classification
- configurable thresholds and policy modes
- structured audit logs
- expanded integration tests against real drivers

## v0.3 — Developer experience

- configuration file support
- polished cross-platform UI
- installer and packaged executables
- health/status endpoint
- local dashboard and query history

## v0.4+ — Database adapters

- MySQL/MariaDB protocol adapter
- SQL Server/TDS adapter
- SQLite wrapper mode
- database-independent policy engine
- IDE and database-client integrations
