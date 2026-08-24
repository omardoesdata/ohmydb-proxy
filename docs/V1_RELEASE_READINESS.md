# OhMyDB v1.0.0 Release Readiness

## Stable release scope

- PostgreSQL safety proxy runtime
- MySQL/MariaDB-compatible protocol support within the documented supported scope
- SQL classification and policy enforcement
- impact estimation where supported
- prepared-statement inspection
- transaction-state tracking and recovery
- fail-closed handling for unknown or ambiguous behavior
- audit logging and sanitization
- CLI configuration
- Docker deployment
- packaging and fresh-wheel installation
- public architecture, threat-model, security, and usage documentation

## Final release requirements

- full automated regression suite passes
- real PostgreSQL E2E matrix passes
- package build and twine metadata checks pass
- fresh-wheel import/runtime checks pass
- Docker runtime checks pass
- CI passes on supported Python versions
- no known release-blocking defects remain

## Known limitations

- TLS termination is not a fully validated supported capability.
- MariaDB Connector/Python native Windows validation remains deferred.
- unsupported or ambiguous prepared-parameter forms intentionally fail closed.
- performance measurements are development baselines, not production guarantees.

## Stable-release principle

OhMyDB is an additional database safety layer and does not replace least privilege, backups, transactions, permissions, or normal database operational controls.
