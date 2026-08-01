from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

from sql_safety_proxy.adapters.mysql.connection import (
    close_stream_writer,
    handle_mysql_connection,
    pump_mysql_backend,
    pump_mysql_client,
)
from sql_safety_proxy.adapters.mysql.relay import (
    MySqlRelayState,
)
from sql_safety_proxy.confirmation import AutoDenyProvider
from sql_safety_proxy.proxy import ProxyOptions


class ScriptedReader:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = list(chunks)
        self.read_calls = 0

    async def read(self, size: int) -> bytes:
        self.read_calls += 1
        await asyncio.sleep(0)

        if self.chunks:
            return self.chunks.pop(0)

        return b""


class BlockingReader:
    def __init__(self) -> None:
        self.cancelled = False

    async def read(self, size: int) -> bytes:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise


class MemoryWriter:
    def __init__(self) -> None:
        self.data = bytearray()
        self.closed = False
        self.wait_closed_calls = 0
        self.drain_calls = 0

    def write(self, data: bytes) -> None:
        self.data.extend(data)

    async def drain(self) -> None:
        self.drain_calls += 1

    def close(self) -> None:
        self.closed = True

    def is_closing(self) -> bool:
        return self.closed

    async def wait_closed(self) -> None:
        self.wait_closed_calls += 1


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
async def test_close_stream_writer_closes_and_waits():
    writer = MemoryWriter()

    await close_stream_writer(writer)

    assert writer.closed is True
    assert writer.wait_closed_calls == 1


@pytest.mark.asyncio
async def test_close_stream_writer_ignores_none():
    await close_stream_writer(None)


@pytest.mark.asyncio
async def test_client_pump_processes_chunks_until_eof(
    monkeypatch,
):
    reader = ScriptedReader([b"one", b"two"])
    backend = MemoryWriter()
    client = MemoryWriter()
    state = MySqlRelayState(database="sql_safety_v06")

    process = AsyncMock(return_value=1)
    monkeypatch.setattr(
        "sql_safety_proxy.adapters.mysql.connection."
        "process_client_chunk",
        process,
    )

    await pump_mysql_client(
        reader=reader,
        backend_writer=backend,
        client_writer=client,
        state=state,
        opts=options(),
    )

    assert process.await_count == 2
    assert process.await_args_list[0].kwargs["chunk"] == b"one"
    assert process.await_args_list[1].kwargs["chunk"] == b"two"


@pytest.mark.asyncio
async def test_client_pump_stops_after_quit(
    monkeypatch,
):
    reader = ScriptedReader([b"quit", b"ignored"])
    backend = MemoryWriter()
    client = MemoryWriter()
    state = MySqlRelayState(database="sql_safety_v06")

    async def process(**kwargs):
        state.session.mark_closing()
        return 1

    monkeypatch.setattr(
        "sql_safety_proxy.adapters.mysql.connection."
        "process_client_chunk",
        process,
    )

    await pump_mysql_client(
        reader=reader,
        backend_writer=backend,
        client_writer=client,
        state=state,
        opts=options(),
    )

    assert reader.read_calls == 1


@pytest.mark.asyncio
async def test_backend_pump_processes_chunks_until_eof(
    monkeypatch,
):
    reader = ScriptedReader([b"handshake", b"response"])
    client = MemoryWriter()
    state = MySqlRelayState(database="sql_safety_v06")

    process = AsyncMock(return_value=1)
    monkeypatch.setattr(
        "sql_safety_proxy.adapters.mysql.connection."
        "process_backend_chunk",
        process,
    )

    await pump_mysql_backend(
        reader=reader,
        client_writer=client,
        state=state,
    )

    assert process.await_count == 2
    assert process.await_args_list[0].kwargs["chunk"] == (
        b"handshake"
    )
    assert process.await_args_list[1].kwargs["chunk"] == (
        b"response"
    )


@pytest.mark.asyncio
async def test_connection_opens_backend_and_closes_writers(
    monkeypatch,
):
    client_reader = ScriptedReader([])
    client_writer = MemoryWriter()
    backend_reader = BlockingReader()
    backend_writer = MemoryWriter()

    open_connection = AsyncMock(
        return_value=(backend_reader, backend_writer)
    )
    monkeypatch.setattr(
        asyncio,
        "open_connection",
        open_connection,
    )

    await handle_mysql_connection(
        client_reader,
        client_writer,
        options(),
    )

    open_connection.assert_awaited_once_with(
        "127.0.0.1",
        3306,
    )
    assert client_writer.closed is True
    assert backend_writer.closed is True
    assert client_writer.wait_closed_calls == 1
    assert backend_writer.wait_closed_calls == 1
    assert backend_reader.cancelled is True


@pytest.mark.asyncio
async def test_backend_connect_failure_still_closes_client(
    monkeypatch,
):
    client_reader = ScriptedReader([])
    client_writer = MemoryWriter()

    monkeypatch.setattr(
        asyncio,
        "open_connection",
        AsyncMock(
            side_effect=OSError("connection refused")
        ),
    )

    await handle_mysql_connection(
        client_reader,
        client_writer,
        options(),
    )

    assert client_writer.closed is True
    assert client_writer.wait_closed_calls == 1


@pytest.mark.asyncio
async def test_protocol_error_closes_both_sides(
    monkeypatch,
):
    client_reader = ScriptedReader([b"bad"])
    client_writer = MemoryWriter()
    backend_reader = BlockingReader()
    backend_writer = MemoryWriter()

    monkeypatch.setattr(
        asyncio,
        "open_connection",
        AsyncMock(
            return_value=(backend_reader, backend_writer)
        ),
    )

    async def fail_client_pump(**kwargs):
        from sql_safety_proxy.adapters.mysql.protocol import (
            MySqlProtocolError,
        )

        raise MySqlProtocolError("malformed packet")

    monkeypatch.setattr(
        "sql_safety_proxy.adapters.mysql.connection."
        "pump_mysql_client",
        fail_client_pump,
    )

    await handle_mysql_connection(
        client_reader,
        client_writer,
        options(),
    )

    assert client_writer.closed is True
    assert backend_writer.closed is True
    assert backend_reader.cancelled is True
