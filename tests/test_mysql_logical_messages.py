from __future__ import annotations

import pytest

from sql_safety_proxy.adapters.mysql.protocol import (
    MAX_PACKET_PAYLOAD,
    MySqlLogicalMessageAssembler,
    MySqlPacket,
    MySqlProtocolError,
    build_packet,
)


def packet(payload: bytes, sequence_id: int) -> MySqlPacket:
    raw = build_packet(payload, sequence_id)
    return MySqlPacket(
        sequence_id=sequence_id,
        payload=payload,
        raw=raw,
    )


def test_single_packet_becomes_one_logical_message():
    assembler = MySqlLogicalMessageAssembler()

    message = assembler.push(packet(b"\x03SELECT 1", 0))

    assert message is not None
    assert message.payload == b"\x03SELECT 1"
    assert message.first_sequence_id == 0
    assert message.last_sequence_id == 0
    assert message.packet_count == 1
    assert assembler.has_partial_message is False


def test_full_size_packet_waits_for_continuation():
    assembler = MySqlLogicalMessageAssembler(
        max_message_bytes=MAX_PACKET_PAYLOAD + 10
    )

    first = packet(b"a" * MAX_PACKET_PAYLOAD, 0)

    assert assembler.push(first) is None
    assert assembler.has_partial_message is True


def test_continuation_packet_completes_logical_message():
    assembler = MySqlLogicalMessageAssembler(
        max_message_bytes=MAX_PACKET_PAYLOAD + 10
    )

    first = packet(b"a" * MAX_PACKET_PAYLOAD, 0)
    second = packet(b"tail", 1)

    assert assembler.push(first) is None

    message = assembler.push(second)

    assert message is not None
    assert message.payload.startswith(b"a" * 20)
    assert message.payload.endswith(b"tail")
    assert len(message.payload) == MAX_PACKET_PAYLOAD + 4
    assert message.first_sequence_id == 0
    assert message.last_sequence_id == 1
    assert message.packet_count == 2
    assert message.raw_packets == first.raw + second.raw


def test_zero_length_terminator_completes_exact_multiple():
    assembler = MySqlLogicalMessageAssembler(
        max_message_bytes=MAX_PACKET_PAYLOAD
    )

    first = packet(b"a" * MAX_PACKET_PAYLOAD, 4)
    terminator = packet(b"", 5)

    assert assembler.push(first) is None

    message = assembler.push(terminator)

    assert message is not None
    assert len(message.payload) == MAX_PACKET_PAYLOAD
    assert message.first_sequence_id == 4
    assert message.last_sequence_id == 5
    assert message.packet_count == 2


def test_sequence_mismatch_is_rejected_and_state_resets():
    assembler = MySqlLogicalMessageAssembler(
        max_message_bytes=MAX_PACKET_PAYLOAD + 10
    )

    assembler.push(packet(b"a" * MAX_PACKET_PAYLOAD, 0))

    with pytest.raises(
        MySqlProtocolError,
        match="sequence mismatch",
    ):
        assembler.push(packet(b"tail", 2))

    assert assembler.has_partial_message is False


def test_message_size_limit_is_enforced():
    assembler = MySqlLogicalMessageAssembler(
        max_message_bytes=5
    )

    with pytest.raises(
        MySqlProtocolError,
        match="exceeds configured maximum",
    ):
        assembler.push(packet(b"123456", 0))

    assert assembler.has_partial_message is False


def test_assembler_can_be_reused_after_completed_message():
    assembler = MySqlLogicalMessageAssembler()

    first = assembler.push(packet(b"one", 0))
    second = assembler.push(packet(b"two", 0))

    assert first is not None
    assert first.payload == b"one"
    assert second is not None
    assert second.payload == b"two"
