# SQL Safety Proxy architecture

## Product goal

Intercept a database command before execution, explain its effect, estimate its
impact, and require an explicit policy decision for risky operations.

## Core pipeline

1. Protocol adapter reconstructs a complete SQL command and bound parameters.
2. Dialect-aware parser creates an AST.
3. Risk rules classify row, schema, permission, and transaction hazards.
4. Preview builder creates a read-only impact query where possible.
5. Estimator adapter runs the preview using least-privilege credentials.
6. Confirmation provider presents CLI, desktop, IDE, or web approval UI.
7. Audit sink records decision metadata without storing secrets by default.

## Adapter model

Universal support is not achieved by pretending all databases share one wire
protocol. Each database family needs:

- `ProtocolAdapter`: PostgreSQL, MySQL/MariaDB, TDS (SQL Server), Oracle, etc.
- `ImpactEstimator`: executes safe previews and obtains metadata/statistics.
- A sqlglot dialect key and database-specific risk extensions.

The classifier and confirmation UI remain shared.

## Current status

- PostgreSQL simple-query protocol: implemented.
- PostgreSQL extended Parse/Bind/Execute protocol: implemented.
- PostgreSQL impact estimator: implemented.
- Native Windows popup and CLI confirmation: implemented.
- Other database protocol adapters: planned, not yet implemented.

## Recommended implementation order

1. Harden PostgreSQL into a reliable v0.1 release.
2. Add audit logs, policies, allowlists, transaction awareness, and tests.
3. Add MySQL/MariaDB protocol adapter.
4. Add SQL Server TDS adapter.
5. Add SQLite wrapper/CLI mode (there is no network wire proxy to intercept).
6. Add IDE integrations and a local control-panel UI.

## v0.3 fail-safe boundary

Protocol execution that cannot be reconstructed is evaluated by `FailSafeMode`. Strict and balanced modes block unknown portals and missing prepared statements. Permissive mode forwards them only for compatibility troubleshooting and records the protocol gap in the audit log.

## v0.4 PostgreSQL hardening boundary

The PostgreSQL adapter now maintains per-connection state for prepared
statements, portals, extended-protocol recovery, and the backend transaction
status reported by `ReadyForQuery` (`I`, `T`, or `E`). `Close` messages remove
local statement or portal state, and statement closure also invalidates
dependent portals.

A proxy-generated extended-protocol error enters recovery mode. Frontend
messages are ignored until `Sync`, matching PostgreSQL's error-recovery model.
Malformed message payloads are converted into fail-safe protocol-gap decisions,
while invalid frame lengths terminate the unsafe client stream with protocol
violation SQLSTATE `08P01`.

Simple Query batches are parsed as a full list rather than only the first AST.
More than one statement is classified as `MULTI_STATEMENT` and evaluated by a
dedicated policy setting.


## v0.5 formal adapter boundary

The adapter registry is the single database-family selection point. An adapter
owns identity, aliases, SQL dialect, default port, capability metadata,
read-only impact estimation, and protocol-runtime startup. PostgreSQL is the
reference implementation.
