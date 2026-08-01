from __future__ import annotations

import pytest

from sql_safety_proxy.adapters.mysql.protocol import (
    CLIENT_CONNECT_WITH_DB,
    CLIENT_PLUGIN_AUTH,
    CLIENT_SECURE_CONNECTION,
    CLIENT_SSL,
    MySqlProtocolError,
    parse_handshake_response,
)


def build_handshake_response(
    *,
    username: str = "proxy_app",
    database: str | None = "sql_safety_v06",
    plugin: str | None = "caching_sha2_password",
    auth_response: bytes = b"secret",
) -> bytes:
    capabilities = CLIENT_SECURE_CONNECTION

    if database is not None:
        capabilities |= CLIENT_CONNECT_WITH_DB

    if plugin is not None:
        capabilities |= CLIENT_PLUGIN_AUTH

    payload = bytearray()
    payload.extend(capabilities.to_bytes(4, "little"))
    payload.extend((16 * 1024 * 1024).to_bytes(4, "little"))
    payload.append(45)
    payload.extend(b"\x00" * 23)

    payload.extend(username.encode("utf-8"))
    payload.append(0)

    payload.append(len(auth_response))
    payload.extend(auth_response)

    if database is not None:
        payload.extend(database.encode("utf-8"))
        payload.append(0)

    if plugin is not None:
        payload.extend(plugin.encode("ascii"))
        payload.append(0)

    return bytes(payload)


def test_parse_handshake_response_extracts_initial_database():
    result = parse_handshake_response(build_handshake_response())

    assert result.username == "proxy_app"
    assert result.database == "sql_safety_v06"
    assert result.auth_plugin == "caching_sha2_password"
    assert result.is_ssl_request is False
    assert result.capability_flags & CLIENT_CONNECT_WITH_DB


def test_parse_handshake_response_allows_no_initial_database():
    result = parse_handshake_response(
        build_handshake_response(database=None)
    )

    assert result.username == "proxy_app"
    assert result.database is None
    assert result.is_ssl_request is False


def test_parse_handshake_response_detects_ssl_request():
    payload = (
        CLIENT_SSL.to_bytes(4, "little")
        + (16 * 1024 * 1024).to_bytes(4, "little")
        + bytes([45])
        + b"\x00" * 23
    )

    result = parse_handshake_response(payload)

    assert result.is_ssl_request is True
    assert result.username == ""
    assert result.database is None


def test_parse_handshake_response_rejects_short_payload():
    with pytest.raises(
        MySqlProtocolError,
        match="shorter than 32 bytes",
    ):
        parse_handshake_response(b"\x00" * 20)


def test_parse_handshake_response_rejects_truncated_auth_data():
    payload = bytearray(
        build_handshake_response(
            database=None,
            plugin=None,
            auth_response=b"secret",
        )
    )

    username_end = payload.index(0, 32)
    auth_length_offset = username_end + 1
    payload[auth_length_offset] = 100

    with pytest.raises(
        MySqlProtocolError,
        match="auth data is truncated",
    ):
        parse_handshake_response(bytes(payload))


def test_parse_handshake_response_rejects_unterminated_username():
    capabilities = CLIENT_SECURE_CONNECTION

    payload = bytearray()
    payload.extend(capabilities.to_bytes(4, "little"))
    payload.extend((16 * 1024 * 1024).to_bytes(4, "little"))
    payload.append(45)
    payload.extend(b"\x00" * 23)
    payload.extend(b"proxy_app")

    with pytest.raises(
        MySqlProtocolError,
        match="username is not null terminated",
    ):
        parse_handshake_response(bytes(payload))
