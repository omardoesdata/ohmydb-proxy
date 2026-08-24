# Examples

These examples connect normal database drivers through OhMyDB.
Use them only with a disposable development database.

The configured host and port must point to the proxy, not directly to the database server.

## PostgreSQL with psycopg

Environment variables:

- `PGHOST` - proxy host; defaults to `127.0.0.1`
- `PGPORT` - proxy port; defaults to `5433`
- `PGUSER`
- `PGPASSWORD`
- `PGDATABASE`

Safe query:

```powershell
python .\examples\postgres_psycopg.py
```

No-WHERE mutation demonstration:

```powershell
python .\examples\postgres_psycopg.py --dangerous-demo
```

With the default safety policy, the dangerous example is expected to be blocked before it reaches PostgreSQL.

## PostgreSQL with asyncpg

The asyncpg example uses the same `PG*` environment variables.

```powershell
python .\examples\postgres_asyncpg.py
```

Dangerous demonstration:

```powershell
python .\examples\postgres_asyncpg.py --dangerous-demo
```

## MySQL/MariaDB with mysql-connector-python

Environment variables:

- `MYSQL_HOST` - proxy host; defaults to `127.0.0.1`
- `MYSQL_PORT` - proxy port; defaults to `3307`
- `MYSQL_USER`
- `MYSQL_PASSWORD`
- `MYSQL_DATABASE`

Safe query:

```powershell
python .\examples\mysql_connector.py
```

Dangerous demonstration:

```powershell
python .\examples\mysql_connector.py --dangerous-demo
```

TLS termination is not currently provided by the MySQL/MariaDB proxy path, so this example disables TLS for the local proxy connection.

## Demo table

Create a disposable table before testing mutation behavior:

```sql
CREATE TABLE sql_safety_demo (
    id INTEGER PRIMARY KEY,
    active BOOLEAN NOT NULL
);
```

Insert disposable test rows as appropriate for your database.

The dangerous examples intentionally omit a `WHERE` clause so the proxy safety policy can be observed.
Never run these demonstrations against production data.
