# SQL Safety Proxy v0.5.0a1

## Highlights

- Formal database-adapter contract and registry.
- Explicit adapter capability metadata.
- PostgreSQL aliases: `postgres`, `postgresql`, and `pg`.
- Proxy startup and impact estimation routed through the selected adapter.
- New primary setting: `DATABASE_ADAPTER`.
- Legacy `DATABASE_ENGINE` and `SQL_DIALECT` remain supported during alpha.
- Adapter conformance tests.
- Real PostgreSQL integration matrix using psycopg Simple Query, psycopg
  extended protocol, and asyncpg.

PostgreSQL remains the only implemented protocol runtime in this release.