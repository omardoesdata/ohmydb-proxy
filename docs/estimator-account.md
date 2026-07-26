# PostgreSQL estimator account

The estimator connection is used only for read-only preview queries. Create a dedicated account rather than reusing an administrator.

Example for a disposable development database:

```sql
CREATE ROLE sql_safety_estimator LOGIN PASSWORD 'replace-this-password';
GRANT CONNECT ON DATABASE testdb TO sql_safety_estimator;
GRANT USAGE ON SCHEMA public TO sql_safety_estimator;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO sql_safety_estimator;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
GRANT SELECT ON TABLES TO sql_safety_estimator;
```

Adjust schema and database names for your environment. Verify the role cannot perform `INSERT`, `UPDATE`, `DELETE`, DDL, role administration, or extension management.
