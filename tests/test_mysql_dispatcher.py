from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

from sql_safety_proxy.adapters.mysql.dispatcher import (
    dispatch_authenticated_command,
)
from sql_safety_proxy.adapters.mysql.protocol import (
    COM_INIT_DB,
    COM_PING,
    COM_QUERY,
    COM_QUIT,
    COM_STMT_EXECUTE,
    COM_STMT_CLOSE,
    COM_STMT_PREPARE,
    COM_STMT_RESET,
    COM_STMT_SEND_LONG_DATA,
    MYSQL_TYPE_BLOB,
    MYSQL_TYPE_LONG,
    MYSQL_TYPE_VAR_STRING,
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


class FailingDrainWriter(MemoryWriter):
    async def drain(self) -> None:
        self.drain_calls += 1
        raise ConnectionResetError("backend drain failed")


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


def register_statement(
    session: MySqlSessionState,
    *,
    sql: str,
    statement_id: int = 42,
    parameter_count: int,
) -> None:
    session.begin_statement_prepare(sql)
    session.complete_statement_prepare(
        statement_id=statement_id,
        parameter_count=parameter_count,
        column_count=0,
    )


def execute_payload(
    values: list[int],
    *,
    new_params_bound: bool = True,
    statement_id: int = 42,
) -> bytes:
    payload = (
        statement_id.to_bytes(4, "little")
        + b"\x00"
        b"\x01\x00\x00\x00"
        + bytes((len(values) + 7) // 8)
        + bytes([int(new_params_bound)])
    )
    if new_params_bound:
        payload += bytes([MYSQL_TYPE_LONG, 0]) * len(values)
    return payload + b"".join(
        value.to_bytes(4, "little", signed=True)
        for value in values
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
async def test_stmt_prepare_is_forwarded_and_recorded():
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

    assert forwarded is True
    assert bytes(backend.data) == logical.raw_packets
    assert bytes(client.data) == b""
    assert session.pending_statement_sql == "SELECT ?"


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
    logical = message(0x0C)

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
    assert b"Unsupported MySQL command 0x0C" in bytes(client.data)


@pytest.mark.asyncio
async def test_ping_is_forwarded_without_sql_classification():
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(database="sql_safety_v06")
    logical = message(COM_PING)

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
    assert session.pending_ping is True


@pytest.mark.asyncio
async def test_ping_with_payload_or_while_ack_pending_is_blocked():
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(database="sql_safety_v06")

    assert await dispatch_authenticated_command(
        message=message(COM_PING, b"unexpected"),
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(FailSafeMode.PERMISSIVE),
    ) is False
    assert bytes(backend.data) == b""

    session.begin_ping()
    assert await dispatch_authenticated_command(
        message=message(COM_PING),
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(FailSafeMode.PERMISSIVE),
    ) is False
    assert bytes(backend.data) == b""


@pytest.mark.asyncio
async def test_pending_ping_blocks_response_producing_commands():
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(database="sql_safety_v06")
    session.begin_ping()

    forwarded = await dispatch_authenticated_command(
        message=message(COM_QUERY, b"SELECT 1"),
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(FailSafeMode.PERMISSIVE),
    )

    assert forwarded is False
    assert bytes(backend.data) == b""
    assert bytes(client.data)[4] == 0xFF
    assert session.pending_ping is True

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


@pytest.mark.asyncio
async def test_stmt_execute_remains_blocked_in_balanced_mode():
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(
        database="sql_safety_v06"
    )
    logical = message(
        COM_STMT_EXECUTE,
        b"\x2a\x00\x00\x00"
        b"\x00"
        b"\x01\x00\x00\x00",
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
    assert b"Protocol gap" in bytes(client.data)
    assert b"Unknown MySQL prepared statement id 42" in bytes(client.data)


@pytest.mark.asyncio
async def test_safe_prepared_mutation_is_inspected_and_forwarded(
    monkeypatch,
):
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(database="sql_safety_v06")
    register_statement(
        session,
        sql="UPDATE safety_users SET active = ? WHERE id = ?",
        parameter_count=2,
    )
    logical = message(
        COM_STMT_EXECUTE,
        execute_payload([0, 42]),
    )
    estimate = AsyncMock(return_value=(0, None))
    monkeypatch.setattr(
        "sql_safety_proxy.adapters.mysql.handler._estimate",
        estimate,
    )

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
    classification = estimate.await_args.args[0]
    assert classification.statement_type == "UPDATE"
    assert classification.preview_query == (
        "SELECT COUNT(*) FROM safety_users WHERE id = 42"
    )
    assert session.prepared_statements[42].parameter_types is not None


@pytest.mark.asyncio
async def test_prepared_execute_reuses_registered_metadata(monkeypatch):
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(database="sql_safety_v06")
    register_statement(
        session,
        sql="SELECT ?",
        parameter_count=1,
    )
    monkeypatch.setattr(
        "sql_safety_proxy.adapters.mysql.handler._estimate",
        AsyncMock(return_value=(None, None)),
    )

    first = message(COM_STMT_EXECUTE, execute_payload([7]))
    second = message(
        COM_STMT_EXECUTE,
        execute_payload([8], new_params_bound=False),
    )

    assert await dispatch_authenticated_command(
        message=first,
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(),
    ) is True
    session.fail_command_forward()
    assert await dispatch_authenticated_command(
        message=second,
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(),
    ) is True
    assert bytes(backend.data) == first.raw_packets + second.raw_packets


@pytest.mark.asyncio
async def test_dangerous_prepared_mutation_is_policy_blocked(monkeypatch):
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(database="sql_safety_v06")
    register_statement(
        session,
        sql="UPDATE safety_users SET active = ?",
        parameter_count=1,
    )
    monkeypatch.setattr(
        "sql_safety_proxy.adapters.mysql.handler._estimate",
        AsyncMock(return_value=(50, None)),
    )
    logical = message(
        COM_STMT_EXECUTE,
        execute_payload([0]),
    )

    forwarded = await dispatch_authenticated_command(
        message=logical,
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(),
    )

    assert forwarded is False
    assert bytes(backend.data) == b""
    assert b"Operation: UPDATE" in bytes(client.data)
    assert session.prepared_statements[42].parameter_types is None


@pytest.mark.asyncio
async def test_malformed_prepared_execute_uses_protocol_gap_policy():
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(database="sql_safety_v06")
    register_statement(
        session,
        sql="SELECT ?",
        parameter_count=1,
    )
    logical = message(
        COM_STMT_EXECUTE,
        b"\x2a\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01",
    )

    forwarded = await dispatch_authenticated_command(
        message=logical,
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(),
    )

    assert forwarded is False
    assert bytes(backend.data) == b""
    assert b"type metadata is truncated" in bytes(client.data)


@pytest.mark.asyncio
async def test_long_data_is_blocked_without_poisoning_session_state():
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(database="sql_safety_v06")
    register_statement(
        session,
        sql="SELECT ?",
        parameter_count=1,
    )
    logical = message(
        COM_STMT_SEND_LONG_DATA,
        b"\x2a\x00\x00\x00\x00\x00secret-bytes",
    )

    forwarded = await dispatch_authenticated_command(
        message=logical,
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(),
    )

    assert forwarded is False
    assert bytes(backend.data) == b""
    assert session.prepared_statements[42].long_data_parameters == set()
    assert b"cannot be inspected" in bytes(client.data)


@pytest.mark.asyncio
async def test_string_parameter_mutation_is_not_row_estimated(monkeypatch):
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(database="sql_safety_v06")
    register_statement(
        session,
        sql="UPDATE users SET active = 0 WHERE name = ?",
        parameter_count=1,
    )
    estimate = AsyncMock(return_value=(0, None))
    monkeypatch.setattr(
        "sql_safety_proxy.adapters.mysql.handler._estimate",
        estimate,
    )
    logical = message(
        COM_STMT_EXECUTE,
        b"\x2a\x00\x00\x00"
        b"\x00\x01\x00\x00\x00"
        b"\x00\x01"
        + bytes([MYSQL_TYPE_VAR_STRING, 0])
        + b"\x01A",
    )

    forwarded = await dispatch_authenticated_command(
        message=logical,
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(),
    )

    assert forwarded is False
    estimate.assert_not_awaited()
    assert bytes(backend.data) == b""
    assert session.prepared_statements[42].parameter_types is None


@pytest.mark.asyncio
async def test_unsupported_parameter_never_reaches_estimator(monkeypatch):
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(database="sql_safety_v06")
    register_statement(
        session,
        sql="SELECT ?",
        parameter_count=1,
    )
    estimate = AsyncMock(return_value=(None, None))
    monkeypatch.setattr(
        "sql_safety_proxy.adapters.mysql.handler._estimate",
        estimate,
    )
    logical = message(
        COM_STMT_EXECUTE,
        b"\x2a\x00\x00\x00"
        b"\x00\x01\x00\x00\x00"
        b"\x00\x01" + bytes([MYSQL_TYPE_BLOB, 0]),
    )

    forwarded = await dispatch_authenticated_command(
        message=logical,
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(FailSafeMode.BALANCED),
    )

    assert forwarded is False
    estimate.assert_not_awaited()
    assert bytes(backend.data) == b""
    assert b"blob parameter type" in bytes(client.data)


@pytest.mark.asyncio
async def test_parameter_metadata_is_not_saved_when_backend_drain_fails(
    monkeypatch,
):
    backend = FailingDrainWriter()
    client = MemoryWriter()
    session = MySqlSessionState(database="sql_safety_v06")
    register_statement(
        session,
        sql="SELECT ?",
        parameter_count=1,
    )
    monkeypatch.setattr(
        "sql_safety_proxy.adapters.mysql.handler._estimate",
        AsyncMock(return_value=(None, None)),
    )
    logical = message(COM_STMT_EXECUTE, execute_payload([7]))

    with pytest.raises(ConnectionResetError, match="drain failed"):
        await dispatch_authenticated_command(
            message=logical,
            session=session,
            backend_writer=backend,
            client_writer=client,
            opts=options(),
        )

    assert session.prepared_statements[42].parameter_types is None


@pytest.mark.asyncio
async def test_known_statement_reset_is_forwarded_and_waits_for_ack():
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(database="sql_safety_v06")
    register_statement(
        session,
        sql="SELECT ?",
        parameter_count=1,
    )
    logical = message(COM_STMT_RESET, b"\x2a\x00\x00\x00")

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
    assert session.pending_statement_reset_id == 42
    assert 42 in session.prepared_statements


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [b"\x2a\x00\x00", b"\x2a\x00\x00\x00\x00", b"\x63\x00\x00\x00"],
)
async def test_malformed_or_unknown_statement_reset_is_always_blocked(payload):
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(database="sql_safety_v06")
    register_statement(
        session,
        sql="SELECT ?",
        parameter_count=1,
    )

    forwarded = await dispatch_authenticated_command(
        message=message(COM_STMT_RESET, payload),
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(FailSafeMode.PERMISSIVE),
    )

    assert forwarded is False
    assert bytes(backend.data) == b""
    assert session.pending_statement_reset_id is None
    assert 42 in session.prepared_statements


@pytest.mark.asyncio
async def test_pending_reset_blocks_second_reset_execute_and_close():
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(database="sql_safety_v06")
    register_statement(
        session,
        sql="SELECT ?",
        parameter_count=1,
    )
    reset = message(COM_STMT_RESET, b"\x2a\x00\x00\x00")
    assert await dispatch_authenticated_command(
        message=reset,
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(),
    ) is True

    for conflicting in (
        reset,
        message(COM_STMT_EXECUTE, execute_payload([7])),
        message(COM_STMT_CLOSE, b"\x2a\x00\x00\x00"),
    ):
        assert await dispatch_authenticated_command(
            message=conflicting,
            session=session,
            backend_writer=backend,
            client_writer=client,
            opts=options(FailSafeMode.PERMISSIVE),
        ) is False

    assert bytes(backend.data) == reset.raw_packets
    assert session.pending_statement_reset_id == 42
    assert 42 in session.prepared_statements


@pytest.mark.asyncio
async def test_reset_drain_failure_clears_pending_ack_without_resetting_statement():
    backend = FailingDrainWriter()
    client = MemoryWriter()
    session = MySqlSessionState(database="sql_safety_v06")
    register_statement(
        session,
        sql="SELECT ?",
        parameter_count=1,
    )
    statement = session.prepared_statements[42]
    statement.parameter_types = ()

    with pytest.raises(ConnectionResetError, match="drain failed"):
        await dispatch_authenticated_command(
            message=message(COM_STMT_RESET, b"\x2a\x00\x00\x00"),
            session=session,
            backend_writer=backend,
            client_writer=client,
            opts=options(),
        )

    assert session.pending_statement_reset_id is None
    assert session.prepared_statements[42] is statement
    assert statement.parameter_types == ()


@pytest.mark.asyncio
async def test_mariadb_pipelined_execute_waits_for_prepare_metadata(
    monkeypatch,
):
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(database="sql_safety_v06")
    session.begin_statement_prepare("SELECT ?")
    monkeypatch.setattr(
        "sql_safety_proxy.adapters.mysql.handler._estimate",
        AsyncMock(return_value=(None, None)),
    )
    execute = message(
        COM_STMT_EXECUTE,
        execute_payload([17], statement_id=0xFFFFFFFF),
    )

    task = asyncio.create_task(
        dispatch_authenticated_command(
            message=execute,
            session=session,
            backend_writer=backend,
            client_writer=client,
            opts=options(),
        )
    )
    await asyncio.sleep(0)
    assert not task.done()
    assert bytes(backend.data) == b""

    session.accept_statement_prepare_ok(
        statement_id=91,
        parameter_count=1,
        column_count=0,
        deprecate_eof=False,
    )
    session.consume_statement_prepare_metadata(
        b"parameter-definition",
        capability_flags=0,
    )
    session.consume_statement_prepare_metadata(
        b"\xfe",
        capability_flags=0,
    )
    await asyncio.sleep(0)
    assert not task.done()

    session.finish_statement_prepare_response()
    assert await task is True
    assert bytes(backend.data) == execute.raw_packets
    assert session.prepared_statements[91].parameter_types is not None


@pytest.mark.asyncio
async def test_mariadb_pipelined_execute_after_failed_prepare_is_blocked():
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(database="sql_safety_v06")
    session.begin_statement_prepare("invalid SQL")
    execute = message(
        COM_STMT_EXECUTE,
        execute_payload([17], statement_id=0xFFFFFFFF),
    )
    task = asyncio.create_task(
        dispatch_authenticated_command(
            message=execute,
            session=session,
            backend_writer=backend,
            client_writer=client,
            opts=options(),
        )
    )
    await asyncio.sleep(0)

    session.fail_statement_prepare()

    assert await task is False
    assert bytes(backend.data) == b""
    assert b"failed COM_STMT_PREPARE" in bytes(client.data)


@pytest.mark.asyncio
async def test_mariadb_last_statement_id_reuses_registered_statement(
    monkeypatch,
):
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(database="sql_safety_v06")
    register_statement(
        session,
        sql="SELECT ?",
        statement_id=73,
        parameter_count=1,
    )
    monkeypatch.setattr(
        "sql_safety_proxy.adapters.mysql.handler._estimate",
        AsyncMock(return_value=(None, None)),
    )
    execute = message(
        COM_STMT_EXECUTE,
        execute_payload([5], statement_id=0xFFFFFFFF),
    )

    assert await dispatch_authenticated_command(
        message=execute,
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(),
    ) is True
    assert session.prepared_statements[73].parameter_types is not None


@pytest.mark.asyncio
async def test_mariadb_last_statement_id_without_prepare_fails_closed():
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(database="sql_safety_v06")

    forwarded = await dispatch_authenticated_command(
        message=message(
            COM_STMT_EXECUTE,
            execute_payload([5], statement_id=0xFFFFFFFF),
        ),
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(),
    )

    assert forwarded is False
    assert bytes(backend.data) == b""
    assert b"No reusable MariaDB prepared statement" in bytes(client.data)


@pytest.mark.asyncio
async def test_blocked_prepared_execution_preserves_transaction_state():
    backend = MemoryWriter()
    client = MemoryWriter()
    session = MySqlSessionState(database="sql_safety_v06")
    session.update_transaction_status(1)
    register_statement(
        session,
        sql="UPDATE safety_users SET active = ?",
        parameter_count=1,
    )

    forwarded = await dispatch_authenticated_command(
        message=message(COM_STMT_EXECUTE, execute_payload([0])),
        session=session,
        backend_writer=backend,
        client_writer=client,
        opts=options(),
    )

    assert forwarded is False
    assert session.transaction_active is True
    assert session.pending_command_response is None
