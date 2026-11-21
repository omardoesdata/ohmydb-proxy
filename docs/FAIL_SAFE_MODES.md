# Fail-Safe Modes

The proxy supports three fail-safe modes for protocol gaps that cannot be safely inspected:

- **STRICT** — blocks uninspectable protocol traffic.
- **BALANCED** — blocks protocol gaps while preserving normal supported protocol handling.
- **PERMISSIVE** — allows the original protocol message to be forwarded.

Protocol-gap decisions remain explicit and auditable.
