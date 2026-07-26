# Security policy

## Supported versions

This project is currently alpha software. Only the latest tagged alpha release receives fixes.

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public GitHub issue.

Until a dedicated security contact is published, open a GitHub Security Advisory through the repository's **Security → Advisories → New draft security advisory** workflow.

Include:

- affected version and operating system
- database client/driver and PostgreSQL version
- minimal reproduction steps
- whether a risky statement was incorrectly forwarded, blocked, or modified
- relevant logs with credentials and private data removed

## Current security boundary

SQL Safety Proxy is an additional human-confirmation guardrail. It is not a substitute for:

- least-privilege database roles
- backups and point-in-time recovery
- change review
- transaction controls
- database auditing
- tested operational procedures

Version `0.1.0-alpha` should only be used with disposable development databases.
