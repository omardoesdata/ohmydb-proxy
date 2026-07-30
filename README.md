# SQL Safety Proxy

SQL Safety Proxy is a local PostgreSQL proxy that evaluates SQL before it
reaches the real database. It classifies risk, estimates affected rows where
possible, applies policy, requests confirmation when required, and writes an
append-only audit record.

## v0.5 capabilities

- PostgreSQL Simple Query protocol.
- PostgreSQL extended `Parse -> Bind -> Execute` protocol.
- Transaction state tracking from backend `ReadyForQuery` messages.
- Correct blocked-query responses for idle, active, and failed transactions.
- Prepared-statement and portal lifecycle tracking, including `Close`.
- Extended-query recovery that discards messages until `Sync` after a block.
- Strict validation of Parse, Bind, Execute, Close, startup, and frame payloads.
- Multi-statement batch detection with a dedicated policy action.
- Read-only row-impact estimation for eligible mutations.
- Policy actions: `ALLOW`, `CONFIRM`, and `BLOCK`.
- Native Tkinter popup and CLI confirmation.
- JSONL audit logging and fail-safe protocol-gap handling.
- Python 3.11, 3.12, and 3.13 CI coverage.

## Installation

```powershell
git clone https://github.com/omardoesdata/sql-safety-proxy
cd sql-safety-proxy
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Configuration

```powershell
$env:DATABASE_ADAPTER = "postgres"
$env:DB_HOST = "127.0.0.1"
$env:DB_PORT = "5432"
$env:PROXY_PORT = "5433"

$env:ESTIMATOR_USER = "postgres"
$env:ESTIMATOR_PASSWORD = "postgres"
$env:DATABASE_ENGINE = "postgres"
$env:SQL_DIALECT = "postgres"
$env:ESTIMATE_TIMEOUT_SECONDS = "8"

$env:CONFIRMATION_MODE = "popup"

$env:POLICY_AUTO_ALLOW_MAX_ROWS = "5"
$env:POLICY_BLOCK_AT_ROWS = "100"
$env:POLICY_NO_WHERE_ACTION = "BLOCK"
$env:POLICY_STRUCTURAL_ACTION = "CONFIRM"
$env:POLICY_UNKNOWN_ACTION = "CONFIRM"
$env:POLICY_ESTIMATION_FAILURE_ACTION = "CONFIRM"
$env:POLICY_MULTI_STATEMENT_ACTION = "BLOCK"

$env:FAIL_SAFE_MODE = "balanced"

$env:AUDIT_ENABLED = "true"
$env:AUDIT_LOG_PATH = "logs\sql-safety-audit.jsonl"
```

Start the proxy:

```powershell
python main.py
```

Point the PostgreSQL client to `127.0.0.1:5433`.

## Transaction and extended-query behavior

The proxy observes PostgreSQL `ReadyForQuery` status values:

- `I`: idle, outside a transaction.
- `T`: inside a valid transaction.
- `E`: inside a failed transaction.

When a Simple Query is blocked, the synthetic response preserves the current
transaction status instead of always claiming the connection is idle. When an
extended-protocol Execute is blocked, the proxy follows PostgreSQL recovery
semantics: subsequent extended messages are discarded until the client sends
`Sync`, which is forwarded to the backend.

## Multi-statement requests

Simple Query requests containing more than one parsed SQL statement are marked
`MULTI_STATEMENT`. They are blocked by default because a single batch can mix
read-only and destructive operations. Configure the behavior with:

```powershell
$env:POLICY_MULTI_STATEMENT_ACTION = "BLOCK" # ALLOW, CONFIRM, or BLOCK
```

## Fail-safe modes

- `strict`: blocks SQL execution when the proxy cannot reconstruct it.
- `balanced`: default; blocks protocol gaps while retaining normal policy
  confirmation for unsupported or unparseable SQL.
- `permissive`: forwards protocol gaps for compatibility troubleshooting and
  records them in the audit log.

## Tests and package build

```powershell
python -m compileall sql_safety_proxy
python -m pytest -v
python -m build
```

## Current limitations

This is an alpha release. It does not terminate PostgreSQL TLS, decode every
binary parameter type, or support non-PostgreSQL wire protocols. Transaction
status is tracked, but v0.4 is not yet a substitute for database permissions,
backups, transaction discipline, or production change controls.


## Database adapter framework

`DATABASE_ADAPTER` is the primary database-family selector. v0.5 registers
PostgreSQL under `postgres`, `postgresql`, and `pg`. Legacy
`DATABASE_ENGINE` and `SQL_DIALECT` remain supported during the alpha
migration period.

## Real PostgreSQL integration matrix

With `sql-safety-postgres-v05` running:

```powershell
python .\scripts\run_v05_integration.py
```
