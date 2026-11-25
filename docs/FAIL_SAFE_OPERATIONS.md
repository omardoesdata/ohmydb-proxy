# Fail-Safe Operations

The SQL safety proxy uses fail-safe modes when protocol traffic cannot be safely inspected.

- **STRICT** blocks uninspectable protocol gaps.
- **BALANCED** blocks protocol gaps while preserving normal supported protocol handling.
- **PERMISSIVE** allows the original protocol message to be forwarded.

Fail-safe decisions are explicit rather than silently treating unsupported protocol states as safe.
