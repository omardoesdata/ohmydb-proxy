"""MySQL and MariaDB database adapter."""

from __future__ import annotations

from typing import Any

from sql_safety_proxy.adapters.base import (
    DatabaseAdapter,
    DatabaseCapabilities,
)
from sql_safety_proxy.risk_estimator import DbConnectionOptions

from .estimator import estimate_mysql_rows


class MySqlAdapter(DatabaseAdapter):
    name = "mysql"
    aliases = ("mariadb",)
    display_name = "MySQL/MariaDB"
    dialect = "mysql"
    default_port = 3306
    default_estimator_user = "proxy_estimator"
    capabilities = DatabaseCapabilities(
        network_proxy=True,
        simple_query=True,
        prepared_statements=False,
        named_portals=False,
        transaction_state=False,
        impact_estimation=True,
        tls_termination=False,
        binary_parameter_oids=False,
    )

    async def estimate_rows(
        self,
        preview_query: str,
        options: DbConnectionOptions,
    ) -> int:
        return await estimate_mysql_rows(preview_query, options)

    async def start_proxy(self, options: Any) -> None:
        raise NotImplementedError(
            "MySQL/MariaDB wire runtime is not enabled in v0.6 phase 1"
        )


MYSQL_ADAPTER = MySqlAdapter()
