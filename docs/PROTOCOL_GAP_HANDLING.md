# Protocol Gap Handling

A protocol gap occurs when the proxy receives protocol state or a message that it cannot reconstruct safely.

Examples include:

- Unknown PostgreSQL portals.
- Unknown prepared statements.
- Malformed frontend messages.
- Other unsupported protocol states.

The proxy evaluates these conditions through the configured fail-safe mode instead of silently treating them as safe SQL.
