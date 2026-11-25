# Protocol Gap Operations

A protocol gap occurs when the proxy cannot safely reconstruct or inspect a database protocol operation.

Examples include:

- Unknown PostgreSQL portals.
- Unknown prepared statements.
- Malformed frontend messages.
- Unsupported protocol states.

These conditions are evaluated through the configured fail-safe policy before traffic is forwarded.
