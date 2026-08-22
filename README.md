# SQL Safety Proxy

SQL Safety Proxy is a developer-facing database safety layer that sits between normal database clients and the database server.

It inspects SQL before execution, classifies risky operations, estimates affected rows where supported, applies policy decisions, and can block or require confirmation before dangerous statements reach the database.

> SQL Safety Proxy is an additional safety layer. It is not a replacement for least privilege, backups, database permissions, transactions, or normal operational safeguards.

## Supported databases

Current validated scope:

- PostgreSQL
- MySQL/MariaDB-compatible server protocol

Validated client paths include:

- psycopg
- asyncpg
- mysql-connector-python

MariaDB Connector/Python on Windows is not currently used as a release gate because of a reproducible native runtime crash in the validation environment.

## Current version

Development version:

```text
0.9.0rc1
```

Latest released pre-release:

```text
v0.7.0a1
```

## Core capabilities

- SQL classification
- policy actions: ALLOW, CONFIRM, BLOCK
- row-impact estimation for supported mutations
- no-WHERE mutation protection
- multi-statement safety handling
- fail-safe protocol-gap behavior
- audit logging
- secret sanitization and redaction
- PostgreSQL Simple Query support
- PostgreSQL extended protocol support
- PostgreSQL prepared statement and portal tracking
- PostgreSQL transaction-state tracking
- MySQL/MariaDB authentication relay
- MySQL/MariaDB session database tracking
- MySQL/MariaDB prepared-statement inspection
- MySQL/MariaDB transaction-state tracking
- Docker deployment
- CLI configuration

## Installation

For development:

```powershell
git clone https://github.com/omardoesdata/sql-safety-proxy
cd sql-safety-proxy
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

For package installation, install the released wheel or package artifact for the desired version.

## CLI

Show help:

```powershell
python -m sql_safety_proxy --help
```

Show version:

```powershell
python -m sql_safety_proxy --version
```

Available CLI overrides:

- `--adapter {postgres,mysql,mariadb}`
- `--port`
- `--db-host`
- `--db-port`
- `--db-name`

CLI values override their corresponding environment variables.

## PostgreSQL quick start

Example development configuration:

```powershell
$env:DATABASE_ADAPTER = "postgres"
$env:DB_HOST = "127.0.0.1"
$env:DB_PORT = "5432"
$env:DB_NAME = "testdb"
$env:PROXY_PORT = "5433"
$env:ESTIMATOR_USER = "proxy_estimator"
$env:ESTIMATOR_PASSWORD = "replace-me"
```

Start the proxy:

```powershell
python -m sql_safety_proxy
```

Then point the PostgreSQL client to:

```text
127.0.0.1:5433
```

The real PostgreSQL server remains on its normal backend address, for example `127.0.0.1:5432`.

## MySQL/MariaDB quick start

Example development configuration:

```powershell
$env:DATABASE_ADAPTER = "mysql"
$env:DB_HOST = "127.0.0.1"
$env:DB_PORT = "3306"
$env:DB_NAME = "testdb"
$env:PROXY_PORT = "3307"
$env:ESTIMATOR_USER = "proxy_estimator"
$env:ESTIMATOR_PASSWORD = "replace-me"
```

Start the proxy:

```powershell
python -m sql_safety_proxy
```

Then point the MySQL/MariaDB client to:

```text
127.0.0.1:3307
```

TLS termination is not currently supported on this proxy path, so compatible clients may need TLS disabled when connecting through the proxy.

## Safe and blocked behavior

Example safe query:

```sql
SELECT * FROM users WHERE id = 1;
```

Example dangerous mutation:

```sql
UPDATE users SET active = 0;
```

With the default no-WHERE safety policy, the second statement is expected to be blocked or otherwise handled according to policy before it reaches the database.

## Policy configuration

Important policy environment variables include:

- `POLICY_AUTO_ALLOW_MAX_ROWS`
- `POLICY_BLOCK_AT_ROWS`
- `POLICY_NO_WHERE_ACTION`
- `POLICY_STRUCTURAL_ACTION`
- `POLICY_UNKNOWN_ACTION`
- `POLICY_ESTIMATION_FAILURE_ACTION`
- `POLICY_MULTI_STATEMENT_ACTION`

Typical actions are `ALLOW`, `CONFIRM`, or `BLOCK` where supported by the policy setting.

## Fail-safe modes

Supported modes include:

- `strict`
- `balanced`
- `permissive`

The default mode is `balanced`.

Fail-safe behavior is intended to prevent unsupported or ambiguous protocol conditions from being silently treated as safe.

## Audit logging

Audit logging can be enabled through environment configuration.

Important variables include:

- `AUDIT_ENABLED`
- `AUDIT_LOG_PATH`

Audit and runtime output are designed to avoid exposing credentials and bound prepared-statement values.

## Prepared statements

PostgreSQL extended-query state is tracked across Parse, Bind, Execute, Close, and Sync flows.

The MySQL/MariaDB path supports validated prepared-statement lifecycle inspection, including statement preparation, execution, reset, close, and supported binary parameter forms.

Unsupported or ambiguous prepared parameter types intentionally fail closed where safe inspection cannot be guaranteed.

## Transactions

Transaction state is tracked for supported PostgreSQL and MySQL/MariaDB runtime paths.

Blocked operations preserve protocol recovery behavior so client and backend state remain synchronized.

## Docker

Build the image:

```powershell
docker build -t sql-safety-proxy:0.9.0rc1 .
```

Check the image:

```powershell
docker run --rm sql-safety-proxy:0.9.0rc1 --version
docker run --rm sql-safety-proxy:0.9.0rc1 --help
```

The image runs as a non-root user and contains the proxy only. It does not bundle PostgreSQL, MySQL, or MariaDB servers.

See `docker-compose.example.yml` for example PostgreSQL and MySQL/MariaDB proxy services.

## Examples

Public driver examples are available in `examples/`:

- `postgres_psycopg.py`
- `postgres_asyncpg.py`
- `mysql_connector.py`

The examples use environment-based credentials and should only be run against disposable development databases.

## Architecture

See:

- `docs/ARCHITECTURE.md`
- `docs/THREAT_MODEL.md`
- `docs/estimator-account.md`

## Known limitations

- TLS termination is not currently a fully validated supported capability.
- MySQL/MariaDB proxy clients may need TLS disabled.
- some prepared-statement parameter categories intentionally fail closed
- SQL classification cannot guarantee complete understanding of every possible dialect construct
- MariaDB Connector/Python on Windows is not a release gate

## Security

See `SECURITY.md` before using the proxy in security-sensitive environments.

Use least-privilege database accounts, a dedicated read-only estimator account, backups, change controls, and normal database security practices alongside the proxy.

## Development and validation

Core validation includes:

```powershell
python -m pytest -q
python -m compileall -q sql_safety_proxy
python -m pip check
git diff --check
python -m build
python -m twine check dist\*
```

Pre-release validation also includes real PostgreSQL and MySQL/MariaDB runtime testing with real clients and representative safe and dangerous queries.

Unit tests alone are not considered sufficient for release validation.

## Roadmap

The current v0.8 phase focuses on productization, documentation, examples, packaging, Docker, and user-facing quality.

The next planned milestone is a release-candidate phase focused on final compatibility, security, performance, and release hardening before v1.0.
