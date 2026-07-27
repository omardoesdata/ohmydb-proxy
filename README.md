# SQL Safety Proxy — Python Prototype

A local PostgreSQL proxy that sits between a database client and the real
server. Before a risky statement executes, it shows a native desktop popup
explaining the risk and, when possible, the estimated number of affected rows.
The query reaches PostgreSQL only after explicit approval.

## Current capabilities

- PostgreSQL wire-protocol pass-through.
- Simple Query protocol support.
- Extended Query protocol support: `Parse → Bind → Execute`.
- Parameterized statements from drivers such as `asyncpg`.
- SQL classification using `sqlglot`.
- Detection of `UPDATE`, `DELETE`, `DROP`, and `TRUNCATE` risks.
- Safe `SELECT COUNT(*)` impact preview for eligible `UPDATE`/`DELETE` queries.
- Native Tkinter popup with **Cancel query** as the safe default.
- CLI confirmation fallback.
- A denied query is not sent to the target database.

## Important prototype limitations

This is not production-ready yet. Before public release, it still needs
stronger protocol coverage, authentication/TLS design, transaction-state
handling, multi-statement policy, broader SQL test fixtures, packaging, audit
logging, and security review.

Binary PostgreSQL parameters are decoded using best-effort heuristics when the
exact type is unavailable. If a trustworthy estimate cannot be produced, the
popup says the estimate is unavailable, but still requires confirmation.

## Windows setup

Use Python 3.11 or newer. Standard Windows Python installations normally include
Tkinter.

```bat
cd sql_safety_proxy_py
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Configure the target database and the proxy's read-only estimator account:

```bat
set DB_HOST=127.0.0.1
set DB_PORT=5432
set PROXY_PORT=5433
set ESTIMATOR_USER=sql_safety_estimator
set ESTIMATOR_PASSWORD=your_read_only_password
set CONFIRMATION_MODE=popup
python main.py
```

You may also double-click `start_proxy.bat` after setting the environment
variables permanently or editing the batch file for local development.

Point your database client to:

- Host: `127.0.0.1`
- Port: `5433`
- Database/user/password: the same values normally used for PostgreSQL

The proxy itself uses `ESTIMATOR_USER` only for read-only preview queries.
Never give that account mutation or administrative privileges.

## Test a blocked query

```bat
python test_query.py "UPDATE users SET active = false;"
```

A popup should appear. Choose **Cancel query**. The client should receive a
blocked-query error and the database should remain unchanged.

## Confirmation modes

Native popup, which is now the default:

```bat
set CONFIRMATION_MODE=popup
```

Terminal prompt fallback:

```bat
set CONFIRMATION_MODE=cli
```

## Project structure

- `main.py` — environment configuration and startup.
- `sql_safety_proxy/proxy.py` — connection interception and policy flow.
- `sql_safety_proxy/pg_protocol.py` — PostgreSQL message framing.
- `sql_safety_proxy/extended_protocol.py` — Parse/Bind/Execute state.
- `sql_safety_proxy/param_decoder.py` — bound-parameter decoding.
- `sql_safety_proxy/sql_classifier.py` — AST-based risk classification.
- `sql_safety_proxy/risk_estimator.py` — read-only impact estimate.
- `sql_safety_proxy/confirmation.py` — confirmation interface and CLI mode.
- `sql_safety_proxy/popup_confirmation.py` — native desktop popup.
- `tests/` — focused local tests.

## Run local popup integration tests

```bat
python -m unittest discover -s tests -v
```

These tests verify that the blocking Tkinter dialog runs outside the asyncio
event loop and that multiple popup requests are serialized.

## v0.2 impact estimation fix

`UPDATE`, `DELETE`, and `TRUNCATE` without a `WHERE` clause now generate a
read-only full-table preview (`SELECT COUNT(*) FROM ...`). The popup therefore
shows the number of rows in the target table instead of `unavailable` whenever
the estimator account can read that table.

New settings:

```powershell
$env:DATABASE_ENGINE = "postgres"
$env:ESTIMATE_TIMEOUT_SECONDS = "8"
```

The estimator connection runs inside a read-only transaction. If the count
cannot be obtained, the query still requires confirmation and the popup shows
the actual estimator error rather than silently skipping protection.

## Multi-database architecture

The SQL classifier and popup are database-independent. Database-specific impact
execution is behind the `ImpactEstimator` interface in
`sql_safety_proxy/risk_estimator.py`. PostgreSQL is the first adapter.

Full support for another database requires two plugins:

1. A wire/interception adapter for that database protocol.
2. An impact-estimator adapter that executes read-only preview SQL.

Planned adapters: MySQL/MariaDB, SQL Server, SQLite/local mode, and Oracle.
