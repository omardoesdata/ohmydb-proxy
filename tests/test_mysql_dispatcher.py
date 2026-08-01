from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from sql_safety_proxy.adapters.mysql.dispatcher import (
    dispatch_authenticated_command,
)
from sql_safety_proxy.adapters.mysql.protocol import (
    COM_INIT_DB,
    COM_QUERY,
    COM_QUIT,
    COM_STMT_PREPARE,
    MySqlLogicalMessage,
    build_packet,
)
from sql_safety_proxy.adapters.mysql.session import (
    MySqlSessionState,
)
from sql_safety_proxy.confirmation import AutoDenyProvider
from sql_safety_proxy.fail_safe import FailSafeMode
from sql_safety_proxy.proxy import ProxyOptions


class MemoryWriter:
    def __init__(self) -> None:
        self.data = bytearray()
        self.drain_calls = 0

    def write(self, data: bytes) -> None:
        self.data.extend(data)

    async def drain(self) -> None:
        self.drain_calls += 1


def options(
    mode: FailSafeMode = FailSafeMode.BALANCED,
) -> ProxyOptions:
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
        fail_safe_mode=mode,
    )


def message(
    command_code: int,
    payload: bytes = b"",
    *,
    sequence_id: int = 0,
) -> MySqlLogicalMessage:
    logical_payload = bytes([command_code]) + payload
    raw = build_packet(logical_payload, sequence_id)

    return MySqlLogicalMessage(
        first_sequence_id=sequence_id,
        last_sequence_id=sequence_id,
        payload=logical_payload,
        raw_packets=raw,
        packet_count=1,
    )


@pytest.mark.asyncio
async def test_query_is_routed_to_query_handler(monkeypatch):
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(
        database="sql_safety_v06"
    )
    logical = message(COM_QUERY, b"SELECT 1")

    handler = AsyncMock(return_value=True)
    monkeypatch.setattr(
        "sql_safety_proxy.adapters.mysql.dispatcher."
        "handle_mysql_query",
        handler,
    )

    forwarded = await dispatch_authenticated_command(
        message=logical,
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(),
    )

    assert forwarded is True
    handler.assert_awaited_once()

    call = handler.await_args.kwargs
    assert call["database"] == "sql_safety_v06"
    assert call["command_payload"] == b"SELECT 1"
    assert call["message"] is logical


@pytest.mark.asyncio
async def test_init_db_is_forwarded_but_not_committed_yet():
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(database="original_db")
    logical = message(COM_INIT_DB, b"new_db")

    forwarded = await dispatch_authenticated_command(
        message=logical,
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(),
    )

    assert forwarded is True
    assert bytes(backend.data) == logical.raw_packets
    assert bytes(client.data) == b""
    assert session.database == "original_db"
    assert session.pending_database == "new_db"


@pytest.mark.asyncio
async def test_empty_init_db_is_fail_safe_blocked():
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(database="original_db")
    logical = message(COM_INIT_DB)

    forwarded = await dispatch_authenticated_command(
        message=logical,
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(FailSafeMode.BALANCED),
    )

    assert forwarded is False
    assert bytes(backend.data) == b""
    assert bytes(client.data)[4] == 0xFF
    assert session.database == "original_db"
    assert session.pending_database is None


@pytest.mark.asyncio
async def test_quit_is_forwarded_and_marks_session_closing():
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(
        database="sql_safety_v06"
    )
    logical = message(COM_QUIT)

    forwarded = await dispatch_authenticated_command(
        message=logical,
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(),
    )

    assert forwarded is True
    assert bytes(backend.data) == logical.raw_packets
    assert bytes(client.data) == b""
    assert session.closing is True


@pytest.mark.asyncio
async def test_prepared_statement_is_blocked_in_balanced_mode():
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(
        database="sql_safety_v06"
    )
    logical = message(
        COM_STMT_PREPARE,
        b"SELECT ?",
    )

    forwarded = await dispatch_authenticated_command(
        message=logical,
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(FailSafeMode.BALANCED),
    )

    assert forwarded is False
    assert bytes(backend.data) == b""
    assert bytes(client.data)[4] == 0xFF
    assert b"prepared-statement" in bytes(client.data)


@pytest.mark.asyncio
async def test_prepared_statement_is_forwarded_in_permissive_mode():
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(
        database="sql_safety_v06"
    )
    logical = message(
        COM_STMT_PREPARE,
        b"SELECT ?",
    )

    forwarded = await dispatch_authenticated_command(
        message=logical,
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(FailSafeMode.PERMISSIVE),
    )

    assert forwarded is True
    assert bytes(backend.data) == logical.raw_packets
    assert bytes(client.data) == b""


@pytest.mark.asyncio
async def test_unknown_command_is_fail_safe_blocked():
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(
        database="sql_safety_v06"
    )
    logical = message(0x0E)

    forwarded = await dispatch_authenticated_command(
        message=logical,
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(FailSafeMode.STRICT),
    )

    assert forwarded is False
    assert bytes(backend.data) == b""
    assert bytes(client.data)[4] == 0xFF
    assert b"Unsupported MySQL command 0x0E" in bytes(client.data)


@pytest.mark.asyncio
async def test_empty_logical_message_is_fail_safe_blocked():
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(
        database="sql_safety_v06"
    )
    logical = MySqlLogicalMessage(
        first_sequence_id=0,
        last_sequence_id=0,
        payload=b"",
        raw_packets=build_packet(b"", 0),
        packet_count=1,
    )

    forwarded = await dispatch_authenticated_command(
        message=logical,
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(FailSafeMode.BALANCED),
    )

    assert forwarded is False
    assert bytes(backend.data) == b""
    assert bytes(client.data)[4] == 0xFF


@pytest.mark.asyncio
async def test_invalid_utf8_query_uses_protocol_gap_policy():
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(
        database="sql_safety_v06"
    )
    logical = message(COM_QUERY, b"\xff\xfe")

    forwarded = await dispatch_authenticated_command(
        message=logical,
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(FailSafeMode.BALANCED),
    )

    assert forwarded is False
    assert bytes(backend.data) == b""
    assert bytes(client.data)[4] == 0xFF
    assert b"invalid UTF-8" in bytes(client.data)
