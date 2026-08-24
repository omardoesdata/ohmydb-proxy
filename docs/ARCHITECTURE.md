# Architecture

## Overview

OhMyDB sits between a normal database client and the real database server.

The high-level request path is:

client -> protocol adapter -> SQL inspection -> policy decision -> backend database

Supporting paths include:

- estimator connection for read-only impact estimation
- confirmation provider for operations requiring human approval
- audit logger for decision and runtime events

## Major components

### CLI and runtime configuration

The CLI builds runtime options from command-line overrides and environment variables, then starts the selected database adapter.

Supported adapter selectors currently include PostgreSQL and MySQL/MariaDB.

### Adapter registry

Database-specific behavior is selected through the adapter layer.

The adapter boundary keeps protocol-specific runtime logic separate from the shared safety concepts used by classification, policy, estimation, confirmation, and audit behavior.

## PostgreSQL path

The PostgreSQL runtime understands supported startup, authentication relay, Simple Query, and extended-query protocol flows.

The extended protocol path tracks objects such as prepared statements and portals and observes transaction state from backend ReadyForQuery messages.

When an extended-protocol operation is blocked, recovery follows PostgreSQL protocol semantics so the client and backend remain synchronized.

## MySQL/MariaDB path

The MySQL/MariaDB runtime handles supported authentication relay, command dispatch, packet framing, session database selection, prepared-statement lifecycle, transaction state, backend relay, and connection cleanup.

Important supported commands include normal query execution and the validated prepared-statement lifecycle used by mysql-connector-python.

Unsupported or ambiguous protocol forms are handled according to fail-safe rules rather than being silently treated as safe.

## SQL classification

SQL statements are classified before dangerous operations are allowed to execute.

Classification identifies categories such as read-only operations, mutations, structural statements, multi-statement requests, and unknown or unsupported forms.

Classification is a safety mechanism, not a mathematical guarantee that every dialect construct can be understood.

## Policy engine

The policy layer converts classification and impact information into an action such as:

- ALLOW
- CONFIRM
- BLOCK

Policy can also define behavior for no-WHERE mutations, structural statements, unknown SQL, estimation failures, and multi-statement requests.

## Impact estimator

For eligible mutations, the proxy can use a separate estimator connection to estimate affected rows before execution.

The estimator should use a dedicated least-privilege read-only database account.

If estimation is unsafe, unsupported, or fails, execution falls back to the configured estimation-failure policy.

## Confirmation providers

Operations classified as requiring approval can be passed to a confirmation provider.

Confirmation output must remain secret-safe and must not expose credentials or bound prepared-statement values.

## Audit logging

The audit layer records important safety decisions and runtime events.

Audit output is sanitized so credentials, SQL parameters, prepared-statement bound values, and other sensitive data are not intentionally emitted.

## Session state

Each proxied connection maintains the protocol state required to interpret subsequent messages safely.

Depending on the database family, this can include:

- active database/schema context
- transaction status
- prepared-statement registry
- portal or statement lifecycle
- cached parameter metadata
- pending protocol acknowledgements
- protocol recovery state

State is bounded and cleaned up when statements or connections are closed.

## Prepared statements

Prepared statements require protocol-aware inspection because the SQL template and bound parameter values may arrive separately.

The supported MySQL/MariaDB path tracks statement IDs, parameter metadata, lifecycle commands, and supported binary parameter representations.

Unsupported or ambiguous parameter types intentionally fail closed where safe inspection cannot be guaranteed.

PostgreSQL extended-query state is also tracked so Parse, Bind, Execute, Close, and Sync behavior can be handled safely.

## Transactions

Transaction state is tracked so blocked operations do not corrupt the client/server protocol state.

PostgreSQL transaction status is derived from backend ReadyForQuery state.

MySQL/MariaDB transaction state is tracked through supported server/session behavior.

## Fail-safe behavior

The proxy is designed to avoid silently weakening protection when SQL or protocol state cannot be interpreted safely.

Fail-safe behavior depends on the configured mode, but protocol gaps, malformed messages, unsupported prepared parameter forms, and unsafe estimation conditions remain explicit and auditable.

## Sanitization

Sanitization is applied to user-facing errors, logs, audit events, startup summaries, and prepared-statement references.

Bound values and credentials must not be included in normal external output.

## Deployment boundary

The proxy can run directly from the Python package or from the provided Docker image.

The Docker image contains the proxy only. It does not bundle a PostgreSQL, MySQL, or MariaDB server.

## Security boundary

OhMyDB is an additional safety layer.

It does not replace database permissions, least privilege, backups, point-in-time recovery, transactions, change controls, or normal database security practices.

See `THREAT_MODEL.md` and the repository `SECURITY.md` for additional security context.
