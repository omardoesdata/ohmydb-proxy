from __future__ import annotations

import pytest

from sql_safety_proxy.adapters.mysql.auth import (
    MySqlAuthPhase,
    MySqlAuthState,
    MySqlBackendAuthPacket,
)
from sql_safety_proxy.adapters.mysql.backend import (
    MySqlBackendPhase,
    MySqlBackendState,
    route_backend_packet,
)
from sql_safety_proxy.adapters.mysql.protocol import (
    CLIENT_CONNECT_WITH_DB,
    CLIENT_PROTOCOL_41,
    SERVER_STATUS_AUTOCOMMIT,
    SERVER_STATUS_IN_TRANS,
    MySqlHandshakeResponse,
    MySqlPacket,
    MySqlProtocolError,
    build_packet,
)
from sql_safety_proxy.adapters.mysql.session import (
    MySqlSessionState,
)


class MemoryWriter:
    def __init__(self) -> None:
        self.data = bytearray()
        self.drain_calls = 0

    def write(self, data: bytes) -> None:
        self.data.extend(data)

    async def drain(self) -> None:
        self.drain_calls += 1


def packet(payload: bytes, sequence_id: int = 2) -> MySqlPacket:
    raw = build_packet(payload, sequence_id)

    return MySqlPacket(
        sequence_id=sequence_id,
        payload=payload,
        raw=raw,
    )


def authenticated_client_response() -> MySqlHandshakeResponse:
    return MySqlHandshakeResponse(
        capability_flags=CLIENT_CONNECT_WITH_DB,
        username="proxy_app",
        database="sql_safety_v06",
        auth_plugin="caching_sha2_password",
        is_ssl_request=False,
    )


def backend_state() -> MySqlBackendState:
    auth = MySqlAuthState(database="configured_db")
    auth.accept_client_response(
        authenticated_client_response()
    )

    return MySqlBackendState(
        auth=auth,
        session=MySqlSessionState(
            database=auth.database
        ),
    )


@pytest.mark.asyncio
async def test_auth_switch_is_forwarded_without_completing_auth():
    state = backend_state()
    client = MemoryWriter()
    backend_packet = packet(
        b"\xfecaching_sha2_password\x00salt"
    )

    result = await route_backend_packet(
        packet=backend_packet,
        state=state,
        client_writer=client,
    )

    assert result == MySqlBackendAuthPacket.AUTH_SWITCH
    assert state.phase == MySqlBackendPhase.AUTHENTICATION
    assert state.auth.phase == MySqlAuthPhase.AUTHENTICATING
    assert bytes(client.data) == backend_packet.raw


@pytest.mark.asyncio
async def test_auth_more_data_is_forwarded_without_completing_auth():
    state = backend_state()
    client = MemoryWriter()
    backend_packet = packet(b"\x01\x04")

    result = await route_backend_packet(
        packet=backend_packet,
        state=state,
        client_writer=client,
    )

    assert result == MySqlBackendAuthPacket.AUTH_MORE_DATA
    assert state.phase == MySqlBackendPhase.AUTHENTICATION
    assert bytes(client.data) == backend_packet.raw


@pytest.mark.asyncio
async def test_backend_ok_completes_authentication():
    state = backend_state()
    client = MemoryWriter()
    backend_packet = packet(b"\x00")

    result = await route_backend_packet(
        packet=backend_packet,
        state=state,
        client_writer=client,
    )

    assert result == MySqlBackendAuthPacket.OK
    assert state.auth.authenticated is True
    assert state.phase == MySqlBackendPhase.COMMAND_RESPONSE
    assert bytes(client.data) == backend_packet.raw


@pytest.mark.asyncio
async def test_backend_error_closes_authentication_state():
    state = backend_state()
    client = MemoryWriter()
    backend_packet = packet(
        b"\xff\x15\x04#28000Access denied"
    )

    result = await route_backend_packet(
        packet=backend_packet,
        state=state,
        client_writer=client,
    )

    assert result == MySqlBackendAuthPacket.ERROR
    assert state.auth.phase == MySqlAuthPhase.FAILED
    assert state.phase == MySqlBackendPhase.CLOSED
    assert bytes(client.data) == backend_packet.raw


@pytest.mark.asyncio
async def test_command_response_is_forwarded_unchanged():
    state = backend_state()
    state.auth.accept_backend_packet(packet(b"\x00"))
    state.mark_authenticated()

    client = MemoryWriter()
    backend_packet = packet(b"\x01column-data", 1)

    result = await route_backend_packet(
        packet=backend_packet,
        state=state,
        client_writer=client,
    )

    assert result is None
    assert bytes(client.data) == backend_packet.raw
    assert client.drain_calls == 1


@pytest.mark.asyncio
async def test_init_db_ok_commits_pending_database():
    state = backend_state()
    state.auth.accept_backend_packet(packet(b"\x00"))
    state.mark_authenticated()
    state.session.begin_database_change("new_db")

    client = MemoryWriter()
    backend_packet = packet(b"\x00", 1)

    await route_backend_packet(
        packet=backend_packet,
        state=state,
        client_writer=client,
    )

    assert state.session.database == "new_db"
    assert state.session.pending_database is None
    assert bytes(client.data) == backend_packet.raw


@pytest.mark.asyncio
async def test_init_db_error_preserves_existing_database():
    state = backend_state()
    state.auth.accept_backend_packet(packet(b"\x00"))
    state.mark_authenticated()
    state.session.begin_database_change("missing_db")

    client = MemoryWriter()
    backend_packet = packet(
        b"\xff\x19\x04#42000Unknown database",
        1,
    )

    await route_backend_packet(
        packet=backend_packet,
        state=state,
        client_writer=client,
    )

    assert state.session.database == "sql_safety_v06"
    assert state.session.pending_database is None
    assert bytes(client.data) == backend_packet.raw


@pytest.mark.asyncio
async def test_unexpected_init_db_response_is_rejected():
    state = backend_state()
    state.auth.accept_backend_packet(packet(b"\x00"))
    state.mark_authenticated()
    state.session.begin_database_change("new_db")

    client = MemoryWriter()

    with pytest.raises(
        MySqlProtocolError,
        match="Unexpected backend response",
    ):
        await route_backend_packet(
            packet=packet(b"\x01\x04", 1),
            state=state,
            client_writer=client,
        )

    assert bytes(client.data) == b""
    assert state.session.pending_database is None


@pytest.mark.asyncio
async def test_packet_after_closed_state_is_rejected():
    state = backend_state()
    state.mark_closed()
    client = MemoryWriter()

    with pytest.raises(
        MySqlProtocolError,
        match="after MySQL connection closed",
    ):
        await route_backend_packet(
            packet=packet(b"\x00"),
            state=state,
            client_writer=client,
        )

    assert bytes(client.data) == b""


def test_mark_authenticated_requires_successful_auth():
    state = backend_state()

    with pytest.raises(
        MySqlProtocolError,
        match="before MySQL authentication succeeds",
    ):
        state.mark_authenticated()


@pytest.mark.asyncio
async def test_prepare_ok_registers_backend_statement_id():
    state = backend_state()
    state.auth.accept_backend_packet(packet(b"\x00"))
    state.mark_authenticated()
    state.session.begin_statement_prepare(
        "UPDATE safety_users SET active = ? WHERE id = ?"
    )

    client = MemoryWriter()
    prepare_ok = packet(
        b"\x00"
        b"\x2a\x00\x00\x00"
        b"\x00\x00"
        b"\x02\x00"
        b"\x00"
        b"\x00\x00",
        1,
    )

    await route_backend_packet(
        packet=prepare_ok,
        state=state,
        client_writer=client,
    )

    statement = state.session.prepared_statements[42]

    assert statement.sql == (
        "UPDATE safety_users SET active = ? WHERE id = ?"
    )
    assert statement.parameter_count == 2
    assert statement.column_count == 0
    assert state.session.pending_statement_sql is not None

    for sequence_id, payload in (
        (2, b"parameter-one"),
        (3, b"parameter-two"),
        (4, b"\xfe"),
    ):
        await route_backend_packet(
            packet=packet(payload, sequence_id),
            state=state,
            client_writer=client,
        )

    assert state.session.pending_statement_sql is None
    assert bytes(client.data).startswith(prepare_ok.raw)


@pytest.mark.asyncio
async def test_prepare_error_discards_pending_statement():
    state = backend_state()
    state.auth.accept_backend_packet(packet(b"\x00"))
    state.mark_authenticated()
    state.session.begin_statement_prepare("SELECT ?")

    client = MemoryWriter()
    prepare_error = packet(
        b"\xff\x15\x04#42000Prepare failed",
        1,
    )

    await route_backend_packet(
        packet=prepare_error,
        state=state,
        client_writer=client,
    )

    assert state.session.pending_statement_sql is None
    assert state.session.prepared_statements == {}
    assert bytes(client.data) == prepare_error.raw


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [b"\x00", b"\xffping failed"])
async def test_ping_ok_or_error_clears_pending_state_and_is_forwarded(payload):
    state = backend_state()
    state.auth.accept_backend_packet(packet(b"\x00"))
    state.mark_authenticated()
    state.session.begin_ping()
    client = MemoryWriter()
    response = packet(payload, 1)

    await route_backend_packet(
        packet=response,
        state=state,
        client_writer=client,
    )

    assert state.session.pending_ping is False
    assert state.phase == MySqlBackendPhase.COMMAND_RESPONSE
    assert bytes(client.data) == response.raw


@pytest.mark.asyncio
async def test_unexpected_ping_response_fails_closed_and_clears_pending_state():
    state = backend_state()
    state.auth.accept_backend_packet(packet(b"\x00"))
    state.mark_authenticated()
    state.session.begin_ping()
    client = MemoryWriter()

    with pytest.raises(MySqlProtocolError, match="COM_PING"):
        await route_backend_packet(
            packet=packet(b"\x01unexpected", 1),
            state=state,
            client_writer=client,
        )

    assert state.session.pending_ping is False
    assert bytes(client.data) == b""


def _register_backend_statement(state, statement_id=42):
    state.session.begin_statement_prepare("SELECT ?")
    return state.session.complete_statement_prepare(
        statement_id=statement_id,
        parameter_count=1,
        column_count=1,
    )


@pytest.mark.asyncio
async def test_reset_ok_clears_metadata_without_removing_statement():
    from sql_safety_proxy.adapters.mysql.protocol import (
        MYSQL_TYPE_LONG,
        MySqlParameterType,
    )

    state = backend_state()
    state.auth.accept_backend_packet(packet(b"\x00"))
    state.mark_authenticated()
    statement = _register_backend_statement(state)
    statement.parameter_types = (MySqlParameterType(MYSQL_TYPE_LONG),)
    statement.long_data_parameters.add(0)
    state.session.begin_statement_reset(42)
    client = MemoryWriter()
    response = packet(b"\x00", 1)

    await route_backend_packet(
        packet=response,
        state=state,
        client_writer=client,
    )

    assert state.session.prepared_statements[42] is statement
    assert statement.parameter_types is None
    assert statement.long_data_parameters == set()
    assert state.session.pending_statement_reset_id is None
    assert bytes(client.data) == response.raw


@pytest.mark.asyncio
async def test_reset_error_preserves_statement_metadata_and_clears_pending():
    from sql_safety_proxy.adapters.mysql.protocol import (
        MYSQL_TYPE_LONG,
        MySqlParameterType,
    )

    state = backend_state()
    state.auth.accept_backend_packet(packet(b"\x00"))
    state.mark_authenticated()
    statement = _register_backend_statement(state)
    parameter_types = (MySqlParameterType(MYSQL_TYPE_LONG),)
    statement.parameter_types = parameter_types
    state.session.begin_statement_reset(42)
    client = MemoryWriter()
    response = packet(b"\xffreset failed", 1)

    await route_backend_packet(
        packet=response,
        state=state,
        client_writer=client,
    )

    assert state.session.prepared_statements[42] is statement
    assert statement.parameter_types == parameter_types
    assert state.session.pending_statement_reset_id is None
    assert bytes(client.data) == response.raw


@pytest.mark.asyncio
async def test_unexpected_reset_response_fails_closed_without_registry_damage():
    state = backend_state()
    state.auth.accept_backend_packet(packet(b"\x00"))
    state.mark_authenticated()
    statement = _register_backend_statement(state)
    state.session.begin_statement_reset(42)
    client = MemoryWriter()

    with pytest.raises(MySqlProtocolError, match="COM_STMT_RESET"):
        await route_backend_packet(
            packet=packet(b"\x01unexpected", 1),
            state=state,
            client_writer=client,
        )

    assert state.session.prepared_statements[42] is statement
    assert state.session.pending_statement_reset_id is None
    assert bytes(client.data) == b""


@pytest.mark.asyncio
async def test_query_ok_updates_transaction_state_and_clears_response():
    state = backend_state()
    state.auth.capability_flags |= CLIENT_PROTOCOL_41
    state.auth.accept_backend_packet(
        packet(b"\x00\x00\x00\x02\x00\x00\x00")
    )
    state.mark_authenticated()
    state.session.begin_command_response("query")
    client = MemoryWriter()
    status = SERVER_STATUS_IN_TRANS | SERVER_STATUS_AUTOCOMMIT
    response = packet(
        b"\x00\x00\x00" + status.to_bytes(2, "little") + b"\x00\x00",
        1,
    )

    await route_backend_packet(
        packet=response,
        state=state,
        client_writer=client,
    )

    assert state.session.transaction_active is True
    assert state.session.autocommit is True
    assert state.session.pending_command_response is None
    assert bytes(client.data) == response.raw


@pytest.mark.asyncio
async def test_query_error_preserves_prior_transaction_state():
    state = backend_state()
    state.auth.accept_backend_packet(packet(b"\x00"))
    state.mark_authenticated()
    state.session.update_transaction_status(SERVER_STATUS_IN_TRANS)
    state.session.begin_command_response("query")
    client = MemoryWriter()

    await route_backend_packet(
        packet=packet(b"\xff\x00\x00query failed", 1),
        state=state,
        client_writer=client,
    )

    assert state.session.transaction_active is True
    assert state.session.pending_command_response is None


@pytest.mark.asyncio
async def test_prepare_metadata_error_invalidates_pipeline_after_forward():
    state = backend_state()
    state.auth.accept_backend_packet(packet(b"\x00"))
    state.mark_authenticated()
    state.session.begin_statement_prepare("SELECT ?")
    event = state.session.pending_prepare_event
    assert event is not None
    client = MemoryWriter()
    prepare_ok = packet(
        b"\x00\x2a\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00",
        1,
    )
    await route_backend_packet(
        packet=prepare_ok,
        state=state,
        client_writer=client,
    )
    metadata_error = packet(b"\xff\x00\x00metadata failed", 2)

    await route_backend_packet(
        packet=metadata_error,
        state=state,
        client_writer=client,
    )

    assert event.is_set()
    assert state.session.last_prepare_failed is True
    assert state.session.prepared_statements == {}
    assert bytes(client.data).endswith(metadata_error.raw)
