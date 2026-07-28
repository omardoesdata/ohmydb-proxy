from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from sql_safety_proxy.confirmation import AutoDenyProvider
from sql_safety_proxy.fail_safe import (
    FailSafeMode,
    ProtocolGapAction,
    evaluate_protocol_gap,
)
from sql_safety_proxy.proxy import (
    ProxyOptions,
    _handle_protocol_gap,
)


class MemoryWriter:
    def __init__(self):
        self.data = bytearray()
        self.drain = AsyncMock()

    def write(self, data: bytes) -> None:
        self.data.extend(data)


def build_options(mode: FailSafeMode, audit_logger=None) -> ProxyOptions:
    return ProxyOptions(
        listen_port=5433,
        target_host="localhost",
        target_port=5432,
        dialect="postgres",
        estimator_user="postgres",
        estimator_password="postgres",
        confirmation_provider=AutoDenyProvider(),
        fail_safe_mode=mode,
        audit_logger=audit_logger,
    )


def test_strict_blocks_protocol_gap():
    result = evaluate_protocol_gap(
        FailSafeMode.STRICT,
        "unknown portal",
    )
    assert result.action == ProtocolGapAction.BLOCK


def test_balanced_blocks_protocol_gap():
    result = evaluate_protocol_gap(
        FailSafeMode.BALANCED,
        "missing statement",
    )
    assert result.action == ProtocolGapAction.BLOCK


def test_permissive_allows_protocol_gap():
    result = evaluate_protocol_gap(
        FailSafeMode.PERMISSIVE,
        "unknown portal",
    )
    assert result.action == ProtocolGapAction.ALLOW


@pytest.mark.asyncio
async def test_balanced_gap_is_blocked_and_audited():
    backend = MemoryWriter()
    client = MemoryWriter()
    logger = SimpleNamespace(log=AsyncMock())

    forwarded = await _handle_protocol_gap(
        protocol="extended",
        reason="Execute referenced unknown portal 'p1'",
        sql="<unavailable>",
        client_writer=client,
        backend_writer=backend,
        raw_message=b"execute",
        database="testdb",
        opts=build_options(FailSafeMode.BALANCED, logger),
    )

    assert forwarded is False
    assert bytes(backend.data) == b""
    assert bytes(client.data).startswith(b"E")
    logger.log.assert_awaited_once()
    event = logger.log.await_args.args[0]
    assert event.final_decision == "BLOCKED_PROTOCOL_GAP"
    assert event.protocol == "extended"


@pytest.mark.asyncio
async def test_permissive_gap_is_forwarded_and_audited():
    backend = MemoryWriter()
    client = MemoryWriter()
    logger = SimpleNamespace(log=AsyncMock())

    forwarded = await _handle_protocol_gap(
        protocol="extended",
        reason="Execute referenced unknown portal 'p1'",
        sql="<unavailable>",
        client_writer=client,
        backend_writer=backend,
        raw_message=b"execute",
        database="testdb",
        opts=build_options(FailSafeMode.PERMISSIVE, logger),
    )

    assert forwarded is True
    assert bytes(backend.data) == b"execute"
    assert bytes(client.data) == b""
    logger.log.assert_awaited_once()
    event = logger.log.await_args.args[0]
    assert event.final_decision == "ALLOWED_PROTOCOL_GAP"
