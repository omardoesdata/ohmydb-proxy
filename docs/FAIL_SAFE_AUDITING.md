# Fail-Safe Auditing

Protocol-gap decisions are represented explicitly in the audit path.

Blocked protocol gaps use the `BLOCKED_PROTOCOL_GAP` final decision.

Forwarded protocol gaps use the `ALLOWED_PROTOCOL_GAP` final decision.

The associated protocol-gap reason is retained so that fail-safe decisions can be investigated after the event.
