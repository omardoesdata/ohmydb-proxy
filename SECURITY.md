# Security Policy

## Supported versions

SQL Safety Proxy is currently pre-release software.

Security fixes are provided for the latest actively maintained pre-release line. Older alpha versions may not receive fixes.

## Reporting a vulnerability

Do not disclose suspected vulnerabilities in a public GitHub issue.

Use GitHub Security Advisories for private disclosure through the repository Security tab.

Please include:

- affected SQL Safety Proxy version
- operating system
- database family and server version
- database client or driver and version
- minimal reproduction steps
- whether an unsafe statement was incorrectly allowed, blocked, or altered
- relevant logs with credentials, SQL parameters, and private data removed
- any known impact on data integrity, authentication, availability, or audit behavior

Do not include real production credentials, confidential SQL data, access tokens, or sensitive database contents.

## Security boundary

SQL Safety Proxy is an additional database safety layer. It is not a replacement for:

- least-privilege database roles
- backups and point-in-time recovery
- database permissions and access controls
- transaction discipline
- code review and change management
- database auditing
- tested operational procedures

## Supported security scope

The current supported scope includes PostgreSQL and MySQL/MariaDB-compatible server protocol paths.

The proxy can classify SQL, estimate affected rows where supported, apply policy decisions, inspect supported prepared statements, track transaction state, and record audit events.

Unknown or ambiguous protocol and SQL cases are intended to follow fail-safe behavior according to the configured mode.

## Known limitations

- TLS termination is not currently a fully validated capability.
- MySQL/MariaDB clients may need TLS disabled when connecting through the proxy.
- Some unsupported prepared-statement parameter forms intentionally fail closed.
- SQL classification cannot mathematically guarantee understanding of every possible dialect construct.
- MariaDB Connector/Python on Windows is not a supported release gate because of a reproducible native runtime crash in the current validation environment.

## Disclosure expectations

Please allow reasonable time for investigation and remediation before public disclosure.

Reports that include a minimal reproduction and clearly describe the expected versus observed behavior are especially helpful.
