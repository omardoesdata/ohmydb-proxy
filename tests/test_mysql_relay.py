from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from sql_safety_proxy.adapters.mysql.auth import (
    MySqlAuthPhase,
)
from sql_safety_proxy.adapters.mysql.backend import (
    MySqlBackendPhase,
)
from sql_safety_proxy.adapters.mysql.protocol import (
    CLIENT_CONNECT_WITH_DB,
    CLIENT_PLUGIN_AUTH,
    CLIENT_SECURE_CONNECTION,
    CLIENT_SSL,
    COM_QUERY,
    MySqlProtocolError,
    build_packet,
)
from sql_safety_proxy.adapters.mysql.relay import (
    MySqlRelayState,
    process_backend_chunk,
    process_client_chunk,
)
from sql_safety_proxy.confirmation import AutoDenyProvider
from sql_safety_proxy.proxy import ProxyOptions


class MemoryWriter:
    def __init__(self) -> None:
        self.data = bytearray()
        self.drain_calls = 0

    def write(self, data: bytes) -> None:
        self.data.extend(data)

    async def drain(self) -> None:
        self.drain_calls += 1


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
        database_name="configured_db",
    )


def handshake_response(
    *,
    database: str | None = "sql_safety_v06",
    ssl_request: bool = False,
    sequence_id: int = 1,
) -> bytes:
    if ssl_request:
        capabilities = CLIENT_SSL
    else:
        capabilities = (
            CLIENT_SECURE_CONNECTION
            | CLIENT_PLUGIN_AUTH
        )
        if database is not None:
            capabilities |= CLIENT_CONNECT_WITH_DB

    payload = bytearray()
    payload.extend(capabilities.to_bytes(4, "little"))
    payload.extend((16 * 1024 * 1024).to_bytes(4, "little"))
    payload.append(45)
    payload.extend(b"\x00" * 23)

    if not ssl_request:
        payload.extend(b"proxy_app\x00")
        payload.append(6)
        payload.extend(b"secret")

        if database is not None:
            payload.extend(database.encode("utf-8"))
            payload.append(0)

        payload.extend(b"caching_sha2_password\x00")

    return build_packet(bytes(payload), sequence_id)


@pytest.mark.asyncio
async def test_backend_handshake_is_forwarded_unchanged():
    state = MySqlRelayState(database="configured_db")
    client = MemoryWriter()
    handshake = build_packet(
        b"\x0a8.4.0\x00server-handshake",
        0,
    )

    processed = await process_backend_chunk(
        chunk=handshake,
        state=state,
        client_writer=client,
    )

    assert processed == 1
    assert bytes(client.data) == handshake
    assert state.initial_backend_handshake_seen is True
    assert state.backend.phase == MySqlBackendPhase.AUTHENTICATION


@pytest.mark.asyncio
async def test_fragmented_backend_handshake_waits_for_full_packet():
    state = MySqlRelayState(database="configured_db")
    client = MemoryWriter()
    handshake = build_packet(b"\x0aserver", 0)

    first = await process_backend_chunk(
        chunk=handshake[:3],
        state=state,
        client_writer=client,
    )
    second = await process_backend_chunk(
        chunk=handshake[3:],
        state=state,
        client_writer=client,
    )

    assert first == 0
    assert second == 1
    assert bytes(client.data) == handshake


@pytest.mark.asyncio
async def test_client_handshake_is_parsed_and_forwarded():
    state = MySqlRelayState(database="configured_db")
    state.initial_backend_handshake_seen = True
    backend = MemoryWriter()
    client = MemoryWriter()
    response = handshake_response()

    processed = await process_client_chunk(
        chunk=response,
        state=state,
        backend_writer=backend,
        client_writer=client,
        opts=options(),
    )

    assert processed == 1
    assert bytes(backend.data) == response
    assert bytes(client.data) == b""
    assert state.auth.phase == MySqlAuthPhase.AUTHENTICATING
    assert state.auth.username == "proxy_app"
    assert state.auth.database == "sql_safety_v06"
    assert state.session.database == "sql_safety_v06"


@pytest.mark.asyncio
async def test_tls_request_is_rejected_without_backend_forward():
    state = MySqlRelayState(database="configured_db")
    state.initial_backend_handshake_seen = True
    backend = MemoryWriter()
    client = MemoryWriter()

    await process_client_chunk(
        chunk=handshake_response(ssl_request=True),
        state=state,
        backend_writer=backend,
        client_writer=client,
        opts=options(),
    )

    assert bytes(backend.data) == b""
    assert bytes(client.data)[4] == 0xFF
    assert b"TLS is unsupported" in bytes(client.data)
    assert state.auth.phase == MySqlAuthPhase.TLS_REJECTED
    assert state.backend.phase == MySqlBackendPhase.CLOSED


@pytest.mark.asyncio
async def test_auth_switch_client_reply_is_forwarded_opaquely():
    state = MySqlRelayState(database="configured_db")
    state.initial_backend_handshake_seen = True
    state.auth.accept_client_response(
        __import__(
            "sql_safety_proxy.adapters.mysql.protocol",
            fromlist=["MySqlHandshakeResponse"],
        ).MySqlHandshakeResponse(
            capability_flags=CLIENT_CONNECT_WITH_DB,
            username="proxy_app",
            database="sql_safety_v06",
            auth_plugin="caching_sha2_password",
            is_ssl_request=False,
        )
    )

    backend = MemoryWriter()
    client = MemoryWriter()
    auth_reply = build_packet(b"opaque-auth-reply", 3)

    await process_client_chunk(
        chunk=auth_reply,
        state=state,
        backend_writer=backend,
        client_writer=client,
        opts=options(),
    )

    assert bytes(backend.data) == auth_reply
    assert bytes(client.data) == b""


@pytest.mark.asyncio
async def test_backend_auth_ok_enters_command_phase():
    state = MySqlRelayState(database="configured_db")
    state.initial_backend_handshake_seen = True
    state.auth.accept_client_response(
        __import__(
            "sql_safety_proxy.adapters.mysql.protocol",
            fromlist=["MySqlHandshakeResponse"],
        ).MySqlHandshakeResponse(
            capability_flags=CLIENT_CONNECT_WITH_DB,
            username="proxy_app",
            database="sql_safety_v06",
            auth_plugin="caching_sha2_password",
            is_ssl_request=False,
        )
    )

    client = MemoryWriter()
    auth_ok = build_packet(b"\x00", 2)

    await process_backend_chunk(
        chunk=auth_ok,
        state=state,
        client_writer=client,
    )

    assert bytes(client.data) == auth_ok
    assert state.auth.authenticated is True
    assert state.backend.phase == MySqlBackendPhase.COMMAND_RESPONSE


@pytest.mark.asyncio
async def test_authenticated_query_reaches_dispatcher(monkeypatch):
    state = MySqlRelayState(database="configured_db")
    state.initial_backend_handshake_seen = True
    state.auth.phase = MySqlAuthPhase.AUTHENTICATED
    state.backend.phase = MySqlBackendPhase.COMMAND_RESPONSE

    backend = MemoryWriter()
    client = MemoryWriter()
    dispatcher = AsyncMock(return_value=True)

    monkeypatch.setattr(
        "sql_safety_proxy.adapters.mysql.relay."
        "dispatch_authenticated_command",
        dispatcher,
    )

    query = build_packet(
        bytes([COM_QUERY]) + b"SELECT 1",
        0,
    )

    await process_client_chunk(
        chunk=query,
        state=state,
        backend_writer=backend,
        client_writer=client,
        opts=options(),
    )

    dispatcher.assert_awaited_once()
    message = dispatcher.await_args.kwargs["message"]
    assert message.payload == b"\x03SELECT 1"


@pytest.mark.asyncio
async def test_fragmented_client_packet_waits_for_completion(
    monkeypatch,
):
    state = MySqlRelayState(database="configured_db")
    state.initial_backend_handshake_seen = True
    state.auth.phase = MySqlAuthPhase.AUTHENTICATED
    state.backend.phase = MySqlBackendPhase.COMMAND_RESPONSE

    backend = MemoryWriter()
    client = MemoryWriter()
    dispatcher = AsyncMock(return_value=True)

    monkeypatch.setattr(
        "sql_safety_proxy.adapters.mysql.relay."
        "dispatch_authenticated_command",
        dispatcher,
    )

    query = build_packet(b"\x03SELECT 1", 0)

    first = await process_client_chunk(
        chunk=query[:5],
        state=state,
        backend_writer=backend,
        client_writer=client,
        opts=options(),
    )
    second = await process_client_chunk(
        chunk=query[5:],
        state=state,
        backend_writer=backend,
        client_writer=client,
        opts=options(),
    )

    assert first == 0
    assert second == 1
    dispatcher.assert_awaited_once()


@pytest.mark.asyncio
async def test_client_before_backend_handshake_is_rejected():
    state = MySqlRelayState(database="configured_db")
    backend = MemoryWriter()
    client = MemoryWriter()

    with pytest.raises(
        MySqlProtocolError,
        match="before the backend handshake",
    ):
        await process_client_chunk(
            chunk=handshake_response(),
            state=state,
            backend_writer=backend,
            client_writer=client,
            opts=options(),
        )


@pytest.mark.asyncio
async def test_client_packet_after_closed_state_is_rejected():
    state = MySqlRelayState(database="configured_db")
    state.initial_backend_handshake_seen = True
    state.auth.phase = MySqlAuthPhase.AUTHENTICATED
    state.backend.phase = MySqlBackendPhase.CLOSED

    backend = MemoryWriter()
    client = MemoryWriter()

    with pytest.raises(
        MySqlProtocolError,
        match="after MySQL connection closed",
    ):
        await process_client_chunk(
            chunk=build_packet(b"\x03SELECT 1", 0),
            state=state,
            backend_writer=backend,
            client_writer=client,
            opts=options(),
        )
