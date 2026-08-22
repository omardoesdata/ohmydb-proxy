# Threat Model

## Purpose

SQL Safety Proxy sits between database clients and database servers and attempts to prevent or interrupt unsafe SQL before execution.

Its primary goal is reducing accidental or unintended destructive database operations. It is not designed to replace database authorization, backups, or operational controls.

## Assets

Primary assets include:

- database data integrity
- database availability
- database credentials
- SQL statements and bound parameter values
- transaction state
- prepared-statement state
- audit records
- policy configuration

## Trust boundaries

The main request path is:

client -> SQL Safety Proxy -> database server

Additional trust boundaries include:

- proxy -> estimator connection
- proxy -> confirmation provider
- proxy -> audit log destination
- application configuration -> proxy runtime

## Threats considered

### Unsafe SQL execution

The primary threat is destructive or high-impact SQL reaching the database when it should have been blocked or confirmed.

Mitigations include SQL classification, policy evaluation, row-impact estimation where supported, transaction-state awareness, and fail-safe handling.

### Protocol ambiguity

Malformed, unsupported, or ambiguous wire-protocol messages can cause the proxy to misunderstand client intent.

The design prefers fail-closed behavior for protocol gaps where safe interpretation is not possible.

### Prepared statements

Prepared statements can hide SQL parameter values from normal text-query inspection.

The MySQL/MariaDB path tracks supported prepared-statement lifecycle state and inspects supported binary parameter forms before execution.

Unsupported or ambiguous prepared parameter forms intentionally fail closed.

### Transaction-state confusion

Incorrect transaction state can lead to invalid recovery behavior or misleading client state.

The proxy tracks transaction status and preserves protocol recovery semantics for supported PostgreSQL and MySQL/MariaDB paths.

### Estimator misuse

The estimator connection must not become a privileged alternate execution path.

Use a dedicated read-only estimator account with the minimum required permissions.

### Secret leakage

Credentials, prepared-statement values, SQL parameters, and private data must not appear in logs, user-facing errors, startup summaries, or audit output.

Sanitization and redaction are part of the runtime hardening model.

### Authentication and transport

The proxy relays or participates in database authentication according to the supported protocol path.

TLS termination is not currently a fully supported validated capability. Operators should not assume the proxy provides encrypted transport termination.

### Denial of service

Large packets, malformed protocol messages, excessive state, connection pressure, or intentionally expensive SQL can affect availability.

Protocol, message, state, and connection limits are used to reduce this risk, but the proxy is not a complete DoS protection layer.

## Fail-safe philosophy

When the proxy cannot safely reconstruct or classify an operation, the intended behavior is to avoid silently weakening safety.

Exact behavior depends on the configured fail-safe mode, but unsupported or ambiguous protocol conditions should remain explicit and auditable.

## Non-goals

SQL Safety Proxy does not attempt to:

- replace database permissions
- replace backups or point-in-time recovery
- guarantee semantic understanding of every SQL dialect feature
- provide a complete database firewall
- provide general network intrusion prevention
- provide full TLS termination for every supported database protocol
- protect against compromised database administrators

## Operator responsibilities

Operators should still use least privilege, dedicated estimator accounts, backups, access controls, test databases, monitoring, and normal production-change procedures.
