# SQL Safety Proxy

SQL Safety Proxy is a local PostgreSQL proxy that evaluates SQL before it
reaches the real database. It classifies risk, estimates affected rows where
possible, applies policy, requests confirmation when required, and writes an
append-only audit record.

## v0.3 capabilities

- PostgreSQL Simple Query protocol.
- PostgreSQL extended `Parse -> Bind -> Execute` protocol.
- `UPDATE`, `DELETE`, `TRUNCATE`, `DROP`, `ALTER`, and `CREATE` classification.
- Read-only row-impact estimation for eligible mutations.
- Policy actions: `ALLOW`, `CONFIRM`, and `BLOCK`.
- Severity levels: `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`.
- Native Tkinter popup and CLI confirmation.
- JSONL audit logging.
- Fail-safe handling for unknown portals and missing prepared statements.
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

$env:FAIL_SAFE_MODE = "balanced"

$env:AUDIT_ENABLED = "true"
$env:AUDIT_LOG_PATH = "logs\sql-safety-audit.jsonl"
```

Start the proxy:

```powershell
python main.py
```

Point the PostgreSQL client to `127.0.0.1:5433`.

## Fail-safe modes

- `strict`: blocks SQL execution when the proxy cannot reconstruct it.
- `balanced`: default; blocks protocol gaps while retaining normal policy
  confirmation for unsupported or unparseable SQL.
- `permissive`: forwards protocol gaps for compatibility troubleshooting and
  records them in the audit log.

Unknown portals and missing prepared statements are protocol gaps. In
`strict` and `balanced` modes they are blocked instead of being silently
forwarded.

## Tests

```powershell
python -m compileall sql_safety_proxy
python -m pytest -v
```

## Current limitations

This is an alpha release. It does not terminate PostgreSQL TLS, fully track
transaction state, decode every binary parameter type, or support non-PostgreSQL
wire protocols. Use a least-privilege estimator account.
