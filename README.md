# SQL Safety Proxy

> A local guardrail for PostgreSQL that pauses risky SQL mutations, explains their impact, and requires explicit approval before forwarding them to the database.

**Status: alpha. PostgreSQL only. Not yet suitable as a sole production safety control.**

SQL Safety Proxy sits between a PostgreSQL client and the actual server. It understands both PostgreSQL's Simple Query protocol and the common extended `Parse → Bind → Execute` flow used by drivers such as `asyncpg`. When it detects a risky statement, it opens a native confirmation dialog or terminal prompt before execution.

## Why this exists

A missing or incorrect `WHERE` clause can update or delete far more data than intended. This tool introduces a deliberate review step immediately before execution:

```text
Database client → SQL Safety Proxy → PostgreSQL
                         │
                         └─ classify → estimate → confirm/block
```

## Current capabilities

- PostgreSQL wire-protocol pass-through
- Simple Query protocol interception
- Extended Query protocol interception
- Parameterized query handling for common scalar values
- AST-based analysis through `sqlglot`
- Warnings for `UPDATE`, `DELETE`, `DROP`, and `TRUNCATE`
- Read-only `COUNT(*)` previews for eligible filtered mutations
- Native Tkinter popup with cancellation as the safe default
- CLI confirmation mode
- Blocked statements are not forwarded to PostgreSQL

## Important limitations

This is an early security-oriented developer tool, not a finished database firewall.

- PostgreSQL is currently the only supported database protocol.
- TLS pass-through is not implemented; clients are told to continue without SSL.
- Some PostgreSQL protocol sequences are not yet fully modeled.
- Binary parameter decoding is best-effort where exact type information is unavailable.
- Multi-statement queries, transaction state, stored procedures, CTE-heavy mutations, joins, and vendor-specific syntax need broader test coverage.
- An unrecognized protocol path may currently be forwarded; review `SECURITY.md` before testing against sensitive systems.
- Use a disposable development database for this release.

## Quick start

Requirements:

- Python 3.11+
- A reachable PostgreSQL instance
- Tkinter for popup mode; it is included in standard Windows Python installations

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e .
```

Set configuration in PowerShell:

```powershell
$env:DB_HOST = "127.0.0.1"
$env:DB_PORT = "5432"
$env:PROXY_PORT = "5433"
$env:ESTIMATOR_USER = "sql_safety_estimator"
$env:ESTIMATOR_PASSWORD = "your-read-only-password"
$env:CONFIRMATION_MODE = "popup"
```

Start the proxy:

```powershell
sql-safety-proxy
```

Point the database client to `127.0.0.1:5433` while keeping its normal PostgreSQL database, user, and password.

## Safe local demonstration

Create a disposable test database and table, then run:

```powershell
python examples/test_query.py "UPDATE users SET active = false;"
```

The popup should explain that the `UPDATE` has no `WHERE` clause. Choosing **Cancel query** blocks it.

## Confirmation modes

Popup:

```powershell
$env:CONFIRMATION_MODE = "popup"
```

CLI:

```powershell
$env:CONFIRMATION_MODE = "cli"
```

## Estimator account

Use a dedicated PostgreSQL account with read-only access. Do not use an administrator or mutation-capable account merely for row previews. Example setup guidance is in [`docs/estimator-account.md`](docs/estimator-account.md).

## Development

```powershell
python -m unittest discover -s tests -v
python -m compileall sql_safety_proxy
```

## Roadmap

- Safer fail-closed handling for unknown protocol states
- Exact PostgreSQL parameter type handling
- Full-table row estimates for unfiltered mutations
- Multi-statement and transaction-aware policy
- Audit logs and configurable organizational policies
- Linux/macOS confirmation providers
- MySQL/MariaDB, SQL Server, and SQLite adapters
- IDE integrations and a local control center

See [`ROADMAP.md`](ROADMAP.md) for the working plan.

## Security

Please do not publish exploitable security findings in a public issue. Follow [`SECURITY.md`](SECURITY.md).

## Contributing

Contributions are welcome. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
