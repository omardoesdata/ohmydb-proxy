from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from sql_safety_proxy.adapters.mysql.handler import (
    handle_mysql_protocol_gap,
    handle_mysql_query,
)
from sql_safety_proxy.adapters.mysql.protocol import (
    MySqlLogicalMessage,
    build_packet,
)
from sql_safety_proxy.confirmation import AutoDenyProvider
from sql_safety_proxy.fail_safe import FailSafeMode
from sql_safety_proxy.policy import (
    PolicyAction,
    PolicyConfig,
)
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
    *,
    policy_config: PolicyConfig | None = None,
    fail_safe_mode: FailSafeMode = FailSafeMode.BALANCED,
    audit_logger=None,
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
        policy_config=policy_config or PolicyConfig(),
        fail_safe_mode=fail_safe_mode,
        audit_logger=audit_logger,
    )


def query_message(
    sql: str,
    *,
    sequence_id: int = 0,
) -> tuple[MySqlLogicalMessage, bytes]:
    command_payload = sql.encode("utf-8")
    payload = b"\x03" + command_payload
    raw = build_packet(payload, sequence_id)

    return (
        MySqlLogicalMessage(
            first_sequence_id=sequence_id,
            last_sequence_id=sequence_id,
            payload=payload,
            raw_packets=raw,
            packet_count=1,
        ),
        command_payload,
    )


@pytest.mark.asyncio
async def test_safe_select_is_forwarded(monkeypatch):
    backend = MemoryWriter()
    client = MemoryWriter()
    message, command_payload = query_message("SELECT 1")

    estimate = AsyncMock(return_value=(None, None))
    monkeypatch.setattr(
        "sql_safety_proxy.adapters.mysql.handler._estimate",
        estimate,
    )

    forwarded = await handle_mysql_query(
        message=message,
        command_payload=command_payload,
        database="sql_safety_v06",
        backend_writer=backend,
        client_writer=client,
        opts=options(),
    )

    assert forwarded is True
    assert bytes(backend.data) == message.raw_packets
    assert bytes(client.data) == b""
    assert backend.drain_calls == 1


@pytest.mark.asyncio
async def test_no_where_update_is_blocked(monkeypatch):
    backend = MemoryWriter()
    client = MemoryWriter()
    message, command_payload = query_message(
        "UPDATE safety_users SET active = 0"
    )

    estimate = AsyncMock(return_value=(50, None))
    monkeypatch.setattr(
        "sql_safety_proxy.adapters.mysql.handler._estimate",
        estimate,
    )

    forwarded = await handle_mysql_query(
        message=message,
        command_payload=command_payload,
        database="sql_safety_v06",
        backend_writer=backend,
        client_writer=client,
        opts=options(
            policy_config=PolicyConfig(
                no_where_action=PolicyAction.BLOCK
            )
        ),
    )

    assert forwarded is False
    assert bytes(backend.data) == b""
    response = bytes(client.data)
    payload_length = int.from_bytes(response[:3], "little")

    assert payload_length == len(response) - 4
    assert response[3] == 1
    assert response[4] == 0xFF
    assert b"Query blocked by sql-safety-proxy" in response
    assert client.drain_calls == 1


@pytest.mark.asyncio
async def test_block_error_uses_next_sequence_id(monkeypatch):
    backend = MemoryWriter()
    client = MemoryWriter()
    message, command_payload = query_message(
        "DROP TABLE safety_users",
        sequence_id=7,
    )

    monkeypatch.setattr(
        "sql_safety_proxy.adapters.mysql.handler._estimate",
        AsyncMock(return_value=(None, None)),
    )

    await handle_mysql_query(
        message=message,
        command_payload=command_payload,
        database="sql_safety_v06",
        backend_writer=backend,
        client_writer=client,
        opts=options(
            policy_config=PolicyConfig(
                structural_action=PolicyAction.BLOCK
            )
        ),
    )

    assert bytes(client.data)[3] == 8


@pytest.mark.asyncio
async def test_strict_protocol_gap_is_blocked_and_audited():
    backend = MemoryWriter()
    client = MemoryWriter()
    logger = SimpleNamespace(
        log=AsyncMock(),
    )

    forwarded = await handle_mysql_protocol_gap(
        reason="Prepared statements are not implemented",
        command_code=0x16,
        raw_message=b"raw-command",
        response_sequence_id=1,
        database="sql_safety_v06",
        backend_writer=backend,
        client_writer=client,
        opts=options(
            fail_safe_mode=FailSafeMode.STRICT,
            audit_logger=logger,
        ),
    )

    assert forwarded is False
    assert bytes(backend.data) == b""
    assert bytes(client.data)[4] == 0xFF
    assert b"Protocol gap" in bytes(client.data)

    logger.log.assert_awaited_once()
    event = logger.log.await_args.args[0]
    assert event.protocol == "mysql-protocol-gap"
    assert event.final_decision == "BLOCKED_PROTOCOL_GAP"
    assert event.database == "sql_safety_v06"


@pytest.mark.asyncio
async def test_permissive_protocol_gap_is_forwarded_and_audited():
    backend = MemoryWriter()
    client = MemoryWriter()
    logger = SimpleNamespace(
        log=AsyncMock(),
    )

    forwarded = await handle_mysql_protocol_gap(
        reason="Unsupported benign command",
        command_code=0x0E,
        raw_message=b"raw-command",
        response_sequence_id=1,
        database="sql_safety_v06",
        backend_writer=backend,
        client_writer=client,
        opts=options(
            fail_safe_mode=FailSafeMode.PERMISSIVE,
            audit_logger=logger,
        ),
    )

    assert forwarded is True
    assert bytes(backend.data) == b"raw-command"
    assert bytes(client.data) == b""

    logger.log.assert_awaited_once()
    event = logger.log.await_args.args[0]
    assert event.final_decision == "ALLOWED_PROTOCOL_GAP"


@pytest.mark.asyncio
async def test_invalid_utf8_query_is_rejected():
    backend = MemoryWriter()
    client = MemoryWriter()
    payload = b"\x03\xff\xfe"
    raw = build_packet(payload, 0)
    message = MySqlLogicalMessage(
        first_sequence_id=0,
        last_sequence_id=0,
        payload=payload,
        raw_packets=raw,
        packet_count=1,
    )

    with pytest.raises(
        ValueError,
        match="invalid UTF-8",
    ):
        await handle_mysql_query(
            message=message,
            command_payload=b"\xff\xfe",
            database="sql_safety_v06",
            backend_writer=backend,
            client_writer=client,
            opts=options(),
        )

    assert bytes(backend.data) == b""
    assert bytes(client.data) == b""
