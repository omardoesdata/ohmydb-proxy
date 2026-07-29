import struct
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from sql_safety_proxy.confirmation import AutoDenyProvider
from sql_safety_proxy.extended_protocol import (
    BindMessage,
    parse_bind_message,
    parse_close_message,
    parse_execute_message,
    parse_parse_message,
)
from sql_safety_proxy.pg_protocol import (
    BackendFramer,
    FrontendMessage,
    FrontendFramer,
    ProtocolMessageError,
    build_ready_for_query,
    parse_ready_for_query_status,
)
from sql_safety_proxy.policy import PolicyAction, PolicyConfig
from sql_safety_proxy.proxy import (
    ConnectionState,
    ProxyOptions,
    _handle_frontend_message,
    _handle_simple_query,
)


class MemoryWriter:
    def __init__(self):
        self.data = bytearray()
        self.drain = AsyncMock()

    def write(self, data: bytes) -> None:
        self.data.extend(data)


def cstring(value: str) -> bytes:
    return value.encode("utf8") + b"\x00"


def frame(message_type: str, payload: bytes) -> bytes:
    return message_type.encode("ascii") + struct.pack(">i", len(payload) + 4) + payload


def parse_payload(name: str, query: str) -> bytes:
    return cstring(name) + cstring(query) + struct.pack(">h", 0)


def bind_payload(portal: str, statement: str) -> bytes:
    return (
        cstring(portal)
        + cstring(statement)
        + struct.pack(">h", 0)
        + struct.pack(">h", 0)
        + struct.pack(">h", 0)
    )


def execute_payload(portal: str, max_rows: int = 0) -> bytes:
    return cstring(portal) + struct.pack(">i", max_rows)


def build_options(policy_config=None):
    return ProxyOptions(
        listen_port=5433,
        target_host="localhost",
        target_port=5432,
        dialect="postgres",
        estimator_user="postgres",
        estimator_password="postgres",
        confirmation_provider=AutoDenyProvider(),
        policy_config=policy_config or PolicyConfig(),
    )


def test_frontend_framer_rejects_invalid_length():
    framer = FrontendFramer()
    with pytest.raises(ProtocolMessageError):
        framer.push(b"Q" + struct.pack(">i", 3))


def test_backend_ready_for_query_status_is_parsed():
    framer = BackendFramer()
    messages = framer.push(build_ready_for_query("T"))
    assert len(messages) == 1
    assert messages[0].type == "Z"
    assert parse_ready_for_query_status(messages[0].payload) == "T"


def test_ready_for_query_rejects_invalid_status():
    with pytest.raises(ProtocolMessageError):
        parse_ready_for_query_status(b"X")


def test_strict_parse_bind_execute_parsers():
    parsed = parse_parse_message(parse_payload("s1", "SELECT 1"))
    assert parsed.statement_name == "s1"
    assert parsed.query == "SELECT 1"

    bind = parse_bind_message(bind_payload("p1", "s1"))
    assert bind.portal_name == "p1"
    assert bind.statement_name == "s1"

    execute = parse_execute_message(execute_payload("p1"))
    assert execute.portal_name == "p1"


def test_parse_rejects_trailing_bytes():
    with pytest.raises(ProtocolMessageError):
        parse_parse_message(parse_payload("s1", "SELECT 1") + b"x")


def test_bind_rejects_bad_format_count():
    payload = cstring("p") + cstring("s") + struct.pack(">h", 2) + struct.pack(">h", 0)
    with pytest.raises(ProtocolMessageError):
        parse_bind_message(payload)


def test_close_parser_supports_statement_and_portal():
    statement = parse_close_message(b"S" + cstring("s1"))
    portal = parse_close_message(b"P" + cstring("p1"))
    assert (statement.target_type, statement.name) == ("S", "s1")
    assert (portal.target_type, portal.name) == ("P", "p1")


def test_connection_state_close_statement_removes_dependent_portals():
    state = ConnectionState()
    state.register_statement("s1", "SELECT 1")
    state.register_portal(BindMessage("p1", "s1"))
    state.close_statement("s1")
    assert "s1" not in state.prepared_statements
    assert "p1" not in state.portals


def test_idle_ready_state_clears_portals_but_keeps_statements():
    state = ConnectionState()
    state.register_statement("s1", "SELECT 1")
    state.register_portal(BindMessage("p1", "s1"))
    state.update_transaction_status("I")
    assert state.transaction_status == "I"
    assert state.prepared_statements["s1"] == "SELECT 1"
    assert state.portals == {}


def test_transaction_ready_state_keeps_portals():
    state = ConnectionState()
    state.register_portal(BindMessage("p1", "s1"))
    state.update_transaction_status("T")
    assert "p1" in state.portals


@pytest.mark.asyncio
async def test_close_message_updates_state_and_is_forwarded():
    state = ConnectionState()
    state.register_statement("s1", "SELECT 1")
    state.register_portal(BindMessage("p1", "s1"))
    backend = MemoryWriter()
    client = MemoryWriter()
    payload = b"P" + cstring("p1")
    raw = frame("C", payload)

    await _handle_frontend_message(
        FrontendMessage("C", payload, raw),
        backend,
        client,
        build_options(),
        state,
    )

    assert "p1" not in state.portals
    assert bytes(backend.data) == raw


@pytest.mark.asyncio
async def test_extended_error_discards_messages_until_sync():
    state = ConnectionState(extended_error_pending=True)
    backend = MemoryWriter()
    client = MemoryWriter()
    parse_raw = frame("P", parse_payload("s1", "SELECT 1"))

    await _handle_frontend_message(
        FrontendMessage("P", parse_raw[5:], parse_raw),
        backend,
        client,
        build_options(),
        state,
    )
    assert bytes(backend.data) == b""
    assert state.prepared_statements == {}

    sync_raw = frame("S", b"")
    await _handle_frontend_message(
        FrontendMessage("S", b"", sync_raw),
        backend,
        client,
        build_options(),
        state,
    )
    assert bytes(backend.data) == sync_raw
    assert state.extended_error_pending is False


@pytest.mark.asyncio
async def test_simple_policy_block_preserves_transaction_status(monkeypatch):
    backend = MemoryWriter()
    client = MemoryWriter()
    state = ConnectionState(transaction_status="T")
    sql = "UPDATE users SET active = false"
    payload = sql.encode() + b"\x00"
    raw = frame("Q", payload)

    async def fake_estimate(*_args, **_kwargs):
        return 10, None

    monkeypatch.setattr("sql_safety_proxy.proxy._estimate", fake_estimate)
    opts = build_options(PolicyConfig(no_where_action=PolicyAction.BLOCK))

    await _handle_simple_query(
        FrontendMessage("Q", payload, raw), backend, client, opts, state
    )

    assert bytes(backend.data) == b""
    assert bytes(client.data).endswith(build_ready_for_query("T"))


@pytest.mark.asyncio
async def test_malformed_extended_message_enters_sync_recovery():
    backend = MemoryWriter()
    client = MemoryWriter()
    state = ConnectionState()
    payload = b"unterminated"
    raw = frame("P", payload)

    await _handle_frontend_message(
        FrontendMessage("P", payload, raw),
        backend,
        client,
        build_options(),
        state,
    )

    assert state.extended_error_pending is True
    assert bytes(backend.data) == b""
    assert bytes(client.data).startswith(b"E")
