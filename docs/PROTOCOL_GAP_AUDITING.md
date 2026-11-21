# Protocol Gap Auditing

Protocol gaps are represented explicitly in the proxy audit path.

Blocked gaps use the `BLOCKED_PROTOCOL_GAP` final decision, while forwarded gaps use `ALLOWED_PROTOCOL_GAP`.

The original protocol and gap reason are retained as part of the audit context so that fail-safe decisions can be investigated after execution.
