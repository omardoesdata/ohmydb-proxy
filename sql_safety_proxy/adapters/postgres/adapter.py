"""PostgreSQL database adapter."""

from __future__ import annotations

import asyncio
from typing import Any

import asyncpg

from sql_safety_proxy.adapters.base import (
    DatabaseAdapter,
    DatabaseCapabilities,
)
from sql_safety_proxy.risk_estimator import DbConnectionOptions


class PostgresAdapter(DatabaseAdapter):
    name = "postgres"
    aliases = ("postgresql", "pg")
    display_name = "PostgreSQL"
    dialect = "postgres"
    default_port = 5432
    capabilities = DatabaseCapabilities(
        network_proxy=True,
        simple_query=True,
        prepared_statements=True,
        named_portals=True,
        transaction_state=True,
        impact_estimation=True,
        tls_termination=False,
        binary_parameter_oids=False,
    )

    async def estimate_rows(
        self,
        preview_query: str,
        options: DbConnectionOptions,
    ) -> int:
        connection = await asyncpg.connect(
            host=options.host,
            port=options.port,
            user=options.user,
            password=options.password,
            database=options.database,
            timeout=options.timeout_seconds,
            command_timeout=options.timeout_seconds,
            ssl=False,
        )

        try:
            async with connection.transaction(readonly=True):
                value = await asyncio.wait_for(
                    connection.fetchval(preview_query),
                    timeout=options.timeout_seconds,
                )
            return int(value or 0)
        finally:
            await connection.close()

    async def start_proxy(self, options: Any) -> None:
        from sql_safety_proxy.proxy import start_postgres_proxy

        self.validate_runtime(options)
        await start_postgres_proxy(options)


POSTGRES_ADAPTER = PostgresAdapter()