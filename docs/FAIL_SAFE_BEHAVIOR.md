# Fail-Safe Protocol Behavior

The SQL Safety Proxy uses explicit fail-safe modes when protocol traffic
cannot be safely inspected.

## Modes

### Strict

Strict mode blocks uninspectable protocol traffic.

### Balanced

Balanced mode blocks uninspectable protocol traffic while supported
operations continue through the normal policy engine.

### Permissive

Permissive mode allows uninspectable protocol traffic to be forwarded.

## Decision flow

```text
Protocol traffic
       |
       v
Can it be safely inspected?
       |
   +---+---+
   |       |
  YES      NO
   |       |
   v       v
Normal   Fail-safe mode
policy       |
             +---------+---------+
             |         |         |
           STRICT   BALANCED  PERMISSIVE
             |         |         |
           BLOCK     BLOCK     ALLOW
The fail-safe layer exists so that unsupported or ambiguous protocol
traffic is handled explicitly rather than silently being treated as safe.

The decision includes both an action and a human-readable reason so that
the result can be surfaced to logs, policy handling, or the client-facing
error path.
