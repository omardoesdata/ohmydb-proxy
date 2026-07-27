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
