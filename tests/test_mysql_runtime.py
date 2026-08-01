from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from sql_safety_proxy.adapters.mysql.runtime import (
    start_mysql_proxy,
)
from sql_safety_proxy.confirmation import AutoDenyProvider
from sql_safety_proxy.proxy import ProxyOptions


class FakeSocket:
    def getsockname(self):
        return ("0.0.0.0", 3307)


class FakeServer:
    def __init__(self) -> None:
        self.sockets = [FakeSocket()]
        self.entered = False
        self.exited = False
        self.serve_forever = AsyncMock()

    async def __aenter__(self):
        self.entered = True
        return self

    async def __aexit__(
        self,
        exc_type,
        exc,
        traceback,
    ):
        self.exited = True


def options() -> ProxyOptions:
    return ProxyOptions(
        listen_port=3307,
        target_host="127.0.0.1",
        target_port=3306,
        dialect="mysql",
        estimator_user="proxy_estimator",
        estimator_password="secret",
        confirmation_provider=AutoDenyProvider(),
        database_engine="mysql",
        adapter_name="mysql",
        database_name="sql_safety_v06",
    )


@pytest.mark.asyncio
async def test_listener_uses_configured_proxy_port(
    monkeypatch,
):
    fake_server = FakeServer()
    start_server = AsyncMock(
        return_value=fake_server
    )

    monkeypatch.setattr(
        "asyncio.start_server",
        start_server,
    )

    await start_mysql_proxy(options())

    start_server.assert_awaited_once()

    call = start_server.await_args

    assert call.kwargs["host"] == "0.0.0.0"
    assert call.kwargs["port"] == 3307
    assert callable(call.args[0])
    assert fake_server.entered is True
    assert fake_server.exited is True
    fake_server.serve_forever.assert_awaited_once()


@pytest.mark.asyncio
async def test_listener_handler_carries_proxy_options(
    monkeypatch,
):
    fake_server = FakeServer()
    captured = {}

    async def start_server(
        handler,
        *,
        host,
        port,
    ):
        captured["handler"] = handler
        captured["host"] = host
        captured["port"] = port
        return fake_server

    monkeypatch.setattr(
        "asyncio.start_server",
        start_server,
    )

    opts = options()

    await start_mysql_proxy(opts)

    handler = captured["handler"]

    assert handler.keywords["opts"] is opts
    assert captured["host"] == "0.0.0.0"
    assert captured["port"] == 3307


@pytest.mark.asyncio
async def test_listener_prints_bound_and_backend_addresses(
    monkeypatch,
    capsys,
):
    fake_server = FakeServer()

    monkeypatch.setattr(
        "asyncio.start_server",
        AsyncMock(return_value=fake_server),
    )

    await start_mysql_proxy(options())

    output = capsys.readouterr().out

    assert "MySQL/MariaDB safety proxy listening" in output
    assert "0.0.0.0" in output
    assert "3307" in output
    assert "127.0.0.1:3306" in output


@pytest.mark.asyncio
async def test_listener_propagates_bind_failure(
    monkeypatch,
):
    monkeypatch.setattr(
        "asyncio.start_server",
        AsyncMock(
            side_effect=OSError(
                "address already in use"
            )
        ),
    )

    with pytest.raises(
        OSError,
        match="address already in use",
    ):
        await start_mysql_proxy(options())
