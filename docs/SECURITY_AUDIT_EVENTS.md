# Security Audit Events

The proxy records security-relevant execution decisions through its audit path.

Audit events can capture:

- the SQL or protocol context being evaluated;
- the classification and policy decision;
- the final execution outcome;
- estimation information or an error when applicable;
- the database and protocol context.

For protocol gaps, the audit record preserves the reason that prevented safe reconstruction or interpretation. This makes fail-safe decisions observable and reviewable without treating an unknown operation as safe.
