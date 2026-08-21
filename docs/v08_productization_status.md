# v0.8 Productization Status

Last updated: 2026-08-14

SQL Safety Proxy v0.8.0a1 is currently under development on `feature/v0.8-productization`.

## Completed

- CLI and configuration UX productization
- Docker support and non-root container validation
- public README restructuring
- updated security policy
- architecture documentation
- threat model
- environment-safe psycopg example
- environment-safe asyncpg example
- environment-safe mysql-connector-python example
- public documentation/example validation tests

## Current validated checkpoint

- feature checkpoint: `af75322`
- full pytest suite: 340 passed
- focused productization/documentation tests: 10 passed
- public documentation/example tests: 5 passed
- Python example compilation: passed
- compileall: passed
- pip check: passed
- git diff --check: passed
- v0.8 wheel build: passed
- v0.8 sdist build: passed
- twine validation for both v0.8 artifacts: passed

## Remaining v0.8 release gates

- real PostgreSQL runtime regression: PASSED (2026-08-15)
- real MariaDB server regression through mysql-connector-python
- prepared-statement and transaction recovery regression: PASSED (2026-08-19)
- secret-leak validation: PASSED (2026-08-18)
- fresh-wheel installation/runtime validation: PASSED (2026-08-16)
- Docker runtime regression: PASSED (2026-08-17)
- final full quality gate: PASSED (2026-08-20)
- pull request and CI
- merge to main
- tag and publish `v0.8.0a1` prerelease

Unit tests alone are not considered sufficient for prerelease validation. Real database instances and real client drivers remain part of the release gate.

MariaDB Connector/Python on Windows remains excluded from the release gate because of the previously isolated native runtime crash.
