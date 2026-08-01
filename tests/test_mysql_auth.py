from __future__ import annotations

import pytest

from sql_safety_proxy.adapters.mysql.auth import (
    MySqlAuthPhase,
    MySqlAuthState,
    MySqlBackendAuthPacket,
    classify_backend_auth_packet,
)
from sql_safety_proxy.adapters.mysql.protocol import (
    CLIENT_CONNECT_WITH_DB,
    CLIENT_SSL,
    MySqlHandshakeResponse,
    MySqlPacket,
    MySqlProtocolError,
)


def packet(payload: bytes, sequence_id: int = 2) -> MySqlPacket:
    raw = (
        len(payload).to_bytes(3, "little")
        + bytes([sequence_id])
        + payload
    )
    return MySqlPacket(
        sequence_id=sequence_id,
        payload=payload,
        raw=raw,
    )


def handshake(
    *,
    database: str | None = "sql_safety_v06",
    ssl_request: bool = False,
) -> MySqlHandshakeResponse:
    capabilities = (
        CLIENT_SSL
        if ssl_request
        else CLIENT_CONNECT_WITH_DB
    )

    return MySqlHandshakeResponse(
        capability_flags=capabilities,
        username="" if ssl_request else "proxy_app",
        database=None if ssl_request else database,
        auth_plugin=(
            None
            if ssl_request
            else "caching_sha2_password"
        ),
        is_ssl_request=ssl_request,
    )


def test_client_handshake_updates_authentication_state():
    state = MySqlAuthState(database="configured_database")

    state.accept_client_response(handshake())

    assert state.phase == MySqlAuthPhase.AUTHENTICATING
    assert state.username == "proxy_app"
    assert state.database == "sql_safety_v06"
    assert state.auth_plugin == "caching_sha2_password"
    assert state.authenticated is False


def test_configured_database_remains_when_client_selects_none():
    state = MySqlAuthState(database="configured_database")

    state.accept_client_response(handshake(database=None))

    assert state.database == "configured_database"
    assert state.phase == MySqlAuthPhase.AUTHENTICATING


def test_tls_request_is_explicitly_rejected():
    state = MySqlAuthState(database="sql_safety_v06")

    state.accept_client_response(
        handshake(ssl_request=True)
    )

    assert state.phase == MySqlAuthPhase.TLS_REJECTED
    assert state.authenticated is False
    assert state.failure_reason is not None
    assert "TLS is unsupported" in state.failure_reason


def test_backend_ok_marks_authentication_complete():
    state = MySqlAuthState(database="sql_safety_v06")
    state.accept_client_response(handshake())

    result = state.accept_backend_packet(packet(b"\x00"))

    assert result == MySqlBackendAuthPacket.OK
    assert state.phase == MySqlAuthPhase.AUTHENTICATED
    assert state.authenticated is True


def test_backend_error_marks_authentication_failed():
    state = MySqlAuthState(database="sql_safety_v06")
    state.accept_client_response(handshake())

    result = state.accept_backend_packet(
        packet(b"\xff\x15\x04#28000Access denied")
    )

    assert result == MySqlBackendAuthPacket.ERROR
    assert state.phase == MySqlAuthPhase.FAILED
    assert state.authenticated is False
    assert state.failure_reason is not None


def test_auth_switch_keeps_authentication_in_progress():
    state = MySqlAuthState(database="sql_safety_v06")
    state.accept_client_response(handshake())

    result = state.accept_backend_packet(
        packet(b"\xfecaching_sha2_password\x00salt")
    )

    assert result == MySqlBackendAuthPacket.AUTH_SWITCH
    assert state.phase == MySqlAuthPhase.AUTHENTICATING


def test_auth_more_data_keeps_authentication_in_progress():
    state = MySqlAuthState(database="sql_safety_v06")
    state.accept_client_response(handshake())

    result = state.accept_backend_packet(
        packet(b"\x01\x04")
    )

    assert result == MySqlBackendAuthPacket.AUTH_MORE_DATA
    assert state.phase == MySqlAuthPhase.AUTHENTICATING


def test_unknown_backend_auth_packet_does_not_complete_auth():
    state = MySqlAuthState(database="sql_safety_v06")
    state.accept_client_response(handshake())

    result = state.accept_backend_packet(
        packet(b"\x02unexpected")
    )

    assert result == MySqlBackendAuthPacket.OTHER
    assert state.phase == MySqlAuthPhase.AUTHENTICATING


def test_empty_backend_auth_packet_is_rejected():
    with pytest.raises(
        MySqlProtocolError,
        match="empty payload",
    ):
        classify_backend_auth_packet(packet(b""))


def test_second_client_handshake_is_rejected():
    state = MySqlAuthState(database="sql_safety_v06")
    state.accept_client_response(handshake())

    with pytest.raises(
        MySqlProtocolError,
        match="invalid authentication phase",
    ):
        state.accept_client_response(handshake())


def test_backend_packet_before_client_response_is_rejected():
    state = MySqlAuthState(database="sql_safety_v06")

    with pytest.raises(
        MySqlProtocolError,
        match="invalid authentication phase",
    ):
        state.accept_backend_packet(packet(b"\x00"))
