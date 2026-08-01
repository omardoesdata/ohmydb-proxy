import pytest

from sql_safety_proxy.adapters.mysql.protocol import (
    COM_QUERY,
    MySqlPacketFramer,
    MySqlProtocolError,
    build_error_packet,
    build_packet,
    parse_command,
    parse_query,
)


def test_mysql_packet_framer_handles_fragmented_packet():
    raw = build_packet(bytes([COM_QUERY]) + b"SELECT 1", 0)
    framer = MySqlPacketFramer()

    assert framer.push(raw[:2]) == []
    assert framer.push(raw[2:5]) == []

    packets = framer.push(raw[5:])
    assert len(packets) == 1
    assert packets[0].raw == raw
    assert packets[0].sequence_id == 0


def test_mysql_packet_framer_handles_multiple_packets():
    first = build_packet(bytes([COM_QUERY]) + b"SELECT 1", 0)
    second = build_packet(bytes([COM_QUERY]) + b"SELECT 2", 0)

    packets = MySqlPacketFramer().push(first + second)
    assert len(packets) == 2


def test_parse_com_query():
    raw = build_packet(bytes([COM_QUERY]) + b"UPDATE t SET x=1", 0)
    packet = MySqlPacketFramer().push(raw)[0]
    command, payload = parse_command(packet)

    assert command == COM_QUERY
    assert parse_query(payload) == "UPDATE t SET x=1"


def test_empty_command_packet_is_rejected():
    packet = MySqlPacketFramer().push(build_packet(b"", 0))[0]

    with pytest.raises(MySqlProtocolError, match="empty"):
        parse_command(packet)


def test_invalid_utf8_query_is_rejected():
    with pytest.raises(MySqlProtocolError, match="UTF-8"):
        parse_query(b"\xff")


def test_mysql_error_packet_has_err_header_and_sqlstate():
    raw = build_error_packet(
        "blocked",
        sequence_id=1,
        sql_state="42000",
    )
    packet = MySqlPacketFramer().push(raw)[0]

    assert packet.sequence_id == 1
    assert packet.payload[0] == 0xFF
    assert packet.payload[3:9] == b"#42000"
