# OhMyDB Demo

This demo shows the core OhMyDB safety flow against PostgreSQL:

1. A normal SELECT passes through the proxy.
2. A risky UPDATE without a WHERE clause is intercepted.
3. OhMyDB classifies the operation as critical.
4. The query is blocked before it modifies the database.
5. A follow-up query verifies that the data remained unchanged.

## Start OhMyDB

    ohmydb --version
    ohmydb

## Connect through the proxy

Connect the PostgreSQL client to the OhMyDB listening port rather than directly to the database backend.

Example:

    psql -h 127.0.0.1 -p 5433 -U postgres -d ohmydb_demo

## Run a normal query

    SELECT id, name, status
    FROM demo_customers
    ORDER BY id;

## Try a dangerous mutation

    UPDATE demo_customers
    SET status = 'inactive';

Because the UPDATE has no WHERE clause, OhMyDB evaluates it as a potentially full-table mutation and applies the configured safety policy before execution.

## Verify the database

    SELECT COUNT(*) AS inactive_customers
    FROM demo_customers
    WHERE status = 'inactive';

When the mutation is blocked, the result remains:

    inactive_customers
    ------------------
    0

## Reset the demo data

To repeat the walkthrough, reset the demo rows before running the risky mutation again:

    UPDATE demo_customers
    SET status = 'active';

Verify the reset:

    SELECT id, name, status
    FROM demo_customers
    ORDER BY id;

This keeps repeated local demonstrations deterministic and avoids carrying state from an earlier run.
## Safety model

OhMyDB can apply:

    ALLOW
    CONFIRM
    BLOCK

The project follows a fail-closed approach for malformed, ambiguous, unsupported, or otherwise unsafe database behavior.

For full configuration and supported protocol details, see the main README.