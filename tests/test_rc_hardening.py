from __future__ import annotations

import asyncio
import json
import random
import struct
from types import SimpleNamespace

import pytest

from sql_safety_proxy.adapters.mysql.protocol import (
    MYSQL_TYPE_LONG,
    MySqlDecodedParameter,
    MySqlLogicalMessageAssembler,
    MySqlPacketFramer,
    MySqlParameterType,
    MySqlProtocolError,
    MySqlStmtExecute,
    build_packet,
    parse_handshake_response,
    parse_resultset_header,
    parse_stmt_execute,
    parse_stmt_execute_parameters,
    reconstruct_stmt_execute_sql,
)
from sql_safety_proxy.adapters.mysql.relay import MySqlRelayState
from sql_safety_proxy.adapters.mysql.session import MySqlSessionState
from sql_safety_proxy.audit import JsonlAuditLogger, build_audit_event
from sql_safety_proxy.confirmation import AutoDenyProvider
from sql_safety_proxy.extended_protocol import (
    parse_bind_message,
    parse_close_message,
    parse_execute_message,
    parse_parse_message,
)
from sql_safety_proxy.pg_protocol import (
    BackendFramer,
    FrontendFramer,
    ProtocolMessageError,
    StartupFramer,
)
from sql_safety_proxy.proxy import (
    ConnectionState,
    ProxyOptions,
    _estimate,
    _pipe_backend,
)
from sql_safety_proxy.sanitization import (
    bound_external_text,
    safe_exception_summary,
    sanitize_sql,
)


SECRET = "RC_SECRET_MARKER_7f91d6"


class ScriptedReader:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = list(chunks)

    async def read(self, _size: int) -> bytes:
        await asyncio.sleep(0)
        return self.chunks.pop(0) if self.chunks else b""


class MemoryWriter:
    def __init__(self) -> None:
        self.data = bytearray()
        self.closed = False

    def write(self, data: bytes) -> None:
        self.data.extend(data)

    async def drain(self) -> None:
        await asyncio.sleep(0)

    def close(self) -> None:
        self.closed = True


def options() -> ProxyOptions:
    return ProxyOptions(
        listen_port=5433,
        target_host="127.0.0.1",
        target_port=5432,
        dialect="postgres",
        estimator_user="estimator",
        estimator_password=SECRET,
        confirmation_provider=AutoDenyProvider(),
    )


def audit_event(index: int = 0):
    return build_audit_event(
        sql=f"UPDATE accounts SET token = '{SECRET}' WHERE id = {index}",
        database="appdb",
        operation="UPDATE",
        target_table="accounts",
        severity="MEDIUM",
        policy_action="BLOCK",
        final_decision="BLOCKED_BY_POLICY",
        estimated_rows=1,
        estimate_error=None,
        classification_reason="targeted update",
        policy_reason="test",
        approximate_estimate=False,
        protocol="test",
    )


def test_startup_framer_handles_fragmentation_and_limits():
    raw = struct.pack(">ii", 13, 196608) + b"u\x00\x00\x00\x00"
    framer = StartupFramer(max_message_bytes=64)
    assert framer.push(raw[:2]) is None
    assert framer.push(raw[2:7]) is None
    assert framer.push(raw[7:]) == raw

    with pytest.raises(ProtocolMessageError, match="exceeds"):
        StartupFramer(max_message_bytes=16).push(struct.pack(">i", 17))
    with pytest.raises(ProtocolMessageError, match="minimum"):
        StartupFramer().push(struct.pack(">i", 7))


@pytest.mark.asyncio
async def test_malformed_backend_state_is_not_forwarded():
    writer = MemoryWriter()
    malformed_ready = b"Z" + struct.pack(">i", 4)
    await _pipe_backend(
        ScriptedReader([malformed_ready]),
        writer,
        ConnectionState(transaction_status="T"),
    )
    assert writer.data == b""
    assert writer.closed is True


def test_postgres_session_registries_are_isolated_and_bounded():
    first = ConnectionState(max_items=1, max_state_bytes=64)
    second = ConnectionState(max_items=1, max_state_bytes=64)
    first.register_statement("one", "SELECT 1")
    second.register_statement("two", "SELECT 2")
    assert set(first.prepared_statements) == {"one"}
    assert set(second.prepared_statements) == {"two"}
    with pytest.raises(ProtocolMessageError, match="registry limit"):
        first.register_statement("overflow", "SELECT 3")
    with pytest.raises(ProtocolMessageError, match="state size"):
        ConnectionState(max_state_bytes=16).register_statement(
            "large", "SELECT " + "x" * 32
        )


def test_mysql_session_registries_are_isolated_and_bounded():
    first = MySqlSessionState(
        database="first", max_prepared_statements=1, max_state_bytes=64
    )
    second = MySqlSessionState(
        database="second", max_prepared_statements=1, max_state_bytes=64
    )
    first.begin_statement_prepare("SELECT ?")
    first.complete_statement_prepare(
        statement_id=1, parameter_count=1, column_count=1
    )
    second.begin_statement_prepare("SELECT ?")
    second.complete_statement_prepare(
        statement_id=2, parameter_count=1, column_count=1
    )
    assert set(first.prepared_statements) == {1}
    assert set(second.prepared_statements) == {2}
    first.begin_statement_prepare("SELECT 2")
    with pytest.raises(MySqlProtocolError, match="registry limit"):
        first.complete_statement_prepare(
            statement_id=3, parameter_count=0, column_count=1
        )


def test_mysql_relay_state_is_independent_per_connection():
    first = MySqlRelayState(database="first")
    second = MySqlRelayState(database="second")
    first.session.transaction_active = True
    first.session.prepared_statements[9] = SimpleNamespace(sql="SELECT 1")
    assert second.session.transaction_active is False
    assert second.session.prepared_statements == {}


def test_invalid_null_bitmap_unused_bits_are_rejected():
    execution = MySqlStmtExecute(
        statement_id=1,
        flags=0,
        iteration_count=1,
        parameter_payload=b"\x80\x01\x03\x00\x01\x00\x00\x00",
    )
    with pytest.raises(MySqlProtocolError, match="out-of-range"):
        parse_stmt_execute_parameters(execution, parameter_count=1)


def test_secret_sanitization_is_bounded_and_removes_credentials():
    sql = (
        f"CREATE USER app PASSWORD '{SECRET}'; "
        f"SELECT '{SECRET}', $$also-{SECRET}$$"
    )
    rendered = sanitize_sql(sql)
    assert SECRET not in rendered
    assert "<redacted>" in rendered or "$redacted$" in rendered
    assert SECRET not in sanitize_sql(
        f"SELECT 'postgres://user:{SECRET}@db.local/app'"
    )
    assert len(bound_external_text("x" * 1000, max_chars=32)) <= 32
    assert SECRET not in safe_exception_summary(
        RuntimeError(SECRET), "database operation"
    )


@pytest.mark.asyncio
async def test_audit_is_concurrent_bounded_rotated_and_secret_safe(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = JsonlAuditLogger(
        path,
        max_file_bytes=1024,
        max_backups=2,
        max_field_chars=128,
    )
    await asyncio.gather(*(logger.log(audit_event(i)) for i in range(30)))
    files = [candidate for candidate in tmp_path.iterdir()]
    assert len(files) <= 3
    combined = "".join(
        candidate.read_text(encoding="utf-8") for candidate in files
    )
    assert SECRET not in combined
    for line in combined.splitlines():
        json.loads(line)


@pytest.mark.asyncio
async def test_estimator_failure_does_not_leak_driver_error(monkeypatch):
    class Adapter:
        async def estimate_rows(self, *_args, **_kwargs):
            raise RuntimeError(f"password={SECRET}")

    monkeypatch.setattr("sql_safety_proxy.proxy.get_adapter", lambda _name: Adapter())
    rows, error = await _estimate(
        SimpleNamespace(preview_query="SELECT COUNT(*) FROM accounts"),
        options(),
        "appdb",
    )
    assert rows is None
    assert error is not None
    assert SECRET not in error


def test_mysql_packet_chunking_property_is_stable():
    rng = random.Random(7007)
    payloads = [rng.randbytes(rng.randrange(0, 80)) for _ in range(30)]
    wire = b"".join(build_packet(payload, i % 256) for i, payload in enumerate(payloads))
    framer = MySqlPacketFramer(max_packet_bytes=1024)
    packets = []
    offset = 0
    while offset < len(wire):
        size = rng.randrange(1, 18)
        packets.extend(framer.push(wire[offset : offset + size]))
        offset += size
    assert [packet.payload for packet in packets] == payloads


@pytest.mark.parametrize("seed", range(12))
def test_binary_parsers_reject_or_return_cleanly_under_deterministic_fuzz(seed):
    rng = random.Random(8100 + seed)
    mysql_parsers = (
        parse_handshake_response,
        lambda data: parse_resultset_header(data, capability_flags=0),
        parse_stmt_execute,
    )
    postgres_parsers = (
        parse_bind_message,
        parse_close_message,
        parse_execute_message,
        parse_parse_message,
    )
    for _ in range(80):
        data = rng.randbytes(rng.randrange(0, 129))
        for parser in mysql_parsers:
            try:
                parser(data)
            except MySqlProtocolError:
                pass
        for parser in postgres_parsers:
            try:
                parser(data)
            except ProtocolMessageError:
                pass

        for framer_type, error_type in (
            (MySqlPacketFramer, MySqlProtocolError),
            (FrontendFramer, ProtocolMessageError),
            (BackendFramer, ProtocolMessageError),
        ):
            try:
                framer_type(max_packet_bytes=1024).push(data) if (
                    framer_type is MySqlPacketFramer
                ) else framer_type(max_message_bytes=1024).push(data)
            except error_type:
                pass


def test_placeholder_reconstruction_property_preserves_non_placeholders():
    parameter = MySqlDecodedParameter(
        type_metadata=MySqlParameterType(MYSQL_TYPE_LONG),
        value=7,
        sql_literal="7",
    )
    for template in (
        "SELECT ?",
        "SELECT '?' AS literal, ?",
        "SELECT `?` AS identifier, ? -- ?\n",
        "SELECT ? /* ordinary ? comment */",
    ):
        reconstructed = reconstruct_stmt_execute_sql(template, (parameter,))
        assert "7" in reconstructed


def test_logical_assembler_state_does_not_cross_instances():
    first = MySqlLogicalMessageAssembler(max_message_bytes=1024)
    second = MySqlLogicalMessageAssembler(max_message_bytes=1024)
    packet = MySqlPacketFramer(max_packet_bytes=1024).push(
        build_packet(b"one", 0)
    )[0]
    assert first.push(packet).payload == b"one"
    assert second.push(packet).payload == b"one"
