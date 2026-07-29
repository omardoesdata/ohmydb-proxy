# SQL Safety Proxy v0.4.0a1

## Highlights

- Backend transaction-state tracking through PostgreSQL `ReadyForQuery`.
- Transaction-aware synthetic responses for blocked Simple Query requests.
- Prepared-statement and portal lifecycle management.
- PostgreSQL `Close` message parsing and local state cleanup.
- Extended-protocol recovery that waits for `Sync` after proxy-generated errors.
- Strict bounds and payload validation for PostgreSQL protocol messages.
- Multi-statement detection with `POLICY_MULTI_STATEMENT_ACTION`.
- Expanded protocol hardening and regression tests.

## Safety changes

Blocked Simple Query requests no longer always return idle status. The proxy
uses the last backend transaction status (`I`, `T`, or `E`). Blocked or malformed
extended-query messages place the proxy into recovery mode; messages are
discarded until `Sync` arrives.

Simple Query batches containing multiple statements are blocked by default.
This prevents a safe first statement from hiding a destructive later statement.

## New configuration

```text
POLICY_MULTI_STATEMENT_ACTION=BLOCK
```

Allowed values are `ALLOW`, `CONFIRM`, and `BLOCK`. The default is `BLOCK`.

## Remaining limitations

This alpha release does not terminate PostgreSQL TLS, fully decode binary
parameter types through OID metadata, or support non-PostgreSQL protocols.
