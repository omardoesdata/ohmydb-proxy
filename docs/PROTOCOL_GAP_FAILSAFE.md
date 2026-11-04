# Protocol Gap Fail-Safe Behavior

When the proxy cannot safely reconstruct or interpret a database protocol operation, it applies the configured fail-safe behavior rather than silently treating the operation as safe.

Protocol-gap decisions are recorded through the existing audit path so that blocked and permitted outcomes remain observable.

This behavior complements the protocol-state recovery mechanisms described in the architecture documentation.
