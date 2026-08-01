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
