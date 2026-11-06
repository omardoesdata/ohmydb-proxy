# Protocol Gap Audit

Protocol gaps occur when the proxy cannot safely reconstruct or interpret a database protocol operation.

The existing fail-safe path records these decisions through the audit system. Protocol-gap audit events include:

- the protocol involved;
- the final decision, such as blocked or allowed;
- the reason that caused the protocol gap.

This keeps protocol-recovery decisions observable instead of silently treating an unrecognized operation as safe.
