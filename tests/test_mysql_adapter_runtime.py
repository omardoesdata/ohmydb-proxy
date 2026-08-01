from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from sql_safety_proxy.adapters.mysql.adapter import (
    MySqlAdapter,
)
from sql_safety_proxy.confirmation import AutoDenyProvider
from sql_safety_proxy.proxy import ProxyOptions


def options(
    *,
    listen_port: int = 3307,
    target_port: int = 3306,
) -> ProxyOptions:
    return ProxyOptions(
        listen_port=listen_port,
        target_host="127.0.0.1",
        target_port=target_port,
        dialect="mysql",
        estimator_user="proxy_estimator",
        estimator_password="secret",
        confirmation_provider=AutoDenyProvider(),
        database_engine="mysql",
        adapter_name="mysql",
        database_name="sql_safety_v06",
    )


@pytest.mark.asyncio
async def test_mysql_adapter_starts_mysql_runtime(
    monkeypatch,
):
    adapter = MySqlAdapter()
    runtime = AsyncMock()

    monkeypatch.setattr(
        "sql_safety_proxy.adapters.mysql.runtime."
        "start_mysql_proxy",
        runtime,
    )

    opts = options()

    await adapter.start_proxy(opts)

    runtime.assert_awaited_once_with(opts)


@pytest.mark.asyncio
async def test_mysql_adapter_validates_listener_port(
    monkeypatch,
):
    adapter = MySqlAdapter()
    runtime = AsyncMock()

    monkeypatch.setattr(
        "sql_safety_proxy.adapters.mysql.runtime."
        "start_mysql_proxy",
        runtime,
    )

    with pytest.raises(
        ValueError,
        match="PROXY_PORT must be between 1 and 65535",
    ):
        await adapter.start_proxy(
            options(listen_port=0)
        )

    runtime.assert_not_awaited()


@pytest.mark.asyncio
async def test_mysql_adapter_validates_backend_port(
    monkeypatch,
):
    adapter = MySqlAdapter()
    runtime = AsyncMock()

    monkeypatch.setattr(
        "sql_safety_proxy.adapters.mysql.runtime."
        "start_mysql_proxy",
        runtime,
    )

    with pytest.raises(
        ValueError,
        match="DB_PORT must be between 1 and 65535",
    ):
        await adapter.start_proxy(
            options(target_port=70000)
        )

    runtime.assert_not_awaited()


def test_mysql_adapter_runtime_capabilities():
    adapter = MySqlAdapter()

    assert adapter.name == "mysql"
    assert "mariadb" in adapter.aliases
    assert adapter.default_port == 3306
    assert adapter.capabilities.network_proxy is True
    assert adapter.capabilities.simple_query is True
    assert adapter.capabilities.prepared_statements is False
    assert adapter.capabilities.tls_termination is False
