# v0.6 MySQL/MariaDB Runtime Validation

Date: 2026-08-02

## Environment

- Operating system: Windows
- MariaDB Server: 12.3.2
- Backend address: 127.0.0.1:3306
- Proxy address: 127.0.0.1:3307
- Test database: sql_safety_v06
- Application user: proxy_app
- Estimator user: proxy_estimator

## Validated behavior

| Test | Result |
|---|---|
| Direct MariaDB connectivity | Passed |
| Authentication through proxy | Passed |
| Safe SELECT through proxy | Passed |
| Targeted UPDATE with WHERE | Passed |
| UPDATE without WHERE | Blocked |
| Row-impact estimation | Passed; estimated 5 rows |
| DROP TABLE | Blocked |
| Blocked statement caused no mutation | Passed |
| Successful COM_INIT_DB / USE | Passed |
| Failed database switch | Passed |
| Authentication failure | Passed |
| TLS connection | Safely rejected |

## Data-integrity verification

After the targeted update, only row ID 1 changed to active=0.
The blocked UPDATE without WHERE did not modify rows 2 through 5.
The blocked DROP TABLE did not remove safety_users.

## Known limitation

When a client requests TLS, the proxy rejects the connection because encrypted
SQL cannot be inspected. MariaDB Connector/C currently reports this as a TLS
SEC_E_INVALID_TOKEN error because the client expects a TLS ServerHello after
the MySQL SSL Request while the proxy returns a plaintext rejection.

TLS termination and inspection are not supported in v0.6.
