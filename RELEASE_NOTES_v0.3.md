# SQL Safety Proxy v0.3.0a1

## Highlights

- Configurable policy engine with ALLOW, CONFIRM, and BLOCK actions.
- Risk severities: LOW, MEDIUM, HIGH, and CRITICAL.
- PostgreSQL row-impact estimation for UPDATE, DELETE, and TRUNCATE.
- JSONL audit logging for policy and user decisions.
- Simple Query and extended Parse/Bind/Execute interception.
- Fail-safe protocol-gap handling with strict, balanced, and permissive modes.
- CI coverage on Python 3.11, 3.12, and 3.13.

## Fail-safe modes

- `strict`: block any SQL execution that cannot be reconstructed.
- `balanced`: block protocol gaps while allowing normal policy confirmation for
  unparseable, unsupported, and estimation-failure cases.
- `permissive`: forward protocol gaps and record `ALLOWED_PROTOCOL_GAP`.
  This mode is intended only for compatibility troubleshooting.

The default mode is `balanced`.

## Audit decisions

The audit log may contain:

- `ALLOWED`
- `APPROVED_BY_USER`
- `BLOCKED_BY_USER`
- `BLOCKED_BY_POLICY`
- `ALLOWED_PROTOCOL_GAP`
- `BLOCKED_PROTOCOL_GAP`

## Remaining limitations

This alpha release does not terminate PostgreSQL TLS, fully track transaction
state, decode every binary parameter type, or support database protocols other
than PostgreSQL.
