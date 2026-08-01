"""MySQL packet framing and command helpers."""

from __future__ import annotations

from dataclasses import dataclass

MAX_PACKET_PAYLOAD = 0xFFFFFF
DEFAULT_MAX_PACKET_BYTES = 64 * 1024 * 1024

COM_QUIT = 0x01
COM_INIT_DB = 0x02
COM_QUERY = 0x03
COM_STMT_PREPARE = 0x16
COM_STMT_EXECUTE = 0x17
COM_STMT_SEND_LONG_DATA = 0x18
COM_STMT_CLOSE = 0x19
COM_STMT_RESET = 0x1A


class MySqlProtocolError(ValueError):
    """Raised when a MySQL packet is malformed or unsupported."""


@dataclass(frozen=True)
class MySqlPacket:
    sequence_id: int
    payload: bytes
    raw: bytes


class MySqlPacketFramer:
    def __init__(
        self,
        max_packet_bytes: int = DEFAULT_MAX_PACKET_BYTES,
    ) -> None:
        if max_packet_bytes < 4:
            raise ValueError("max_packet_bytes must be at least 4")
        self._buffer = bytearray()
        self._max_packet_bytes = max_packet_bytes

    def push(self, chunk: bytes) -> list[MySqlPacket]:
        self._buffer.extend(chunk)
        packets: list[MySqlPacket] = []

        while True:
            if len(self._buffer) < 4:
                break

            payload_length = int.from_bytes(self._buffer[:3], "little")
            total_length = payload_length + 4

            if total_length > self._max_packet_bytes:
                raise MySqlProtocolError(
                    f"MySQL packet size {total_length} exceeds "
                    f"configured maximum {self._max_packet_bytes}"
                )

            if len(self._buffer) < total_length:
                break

            raw = bytes(self._buffer[:total_length])
            del self._buffer[:total_length]

            packets.append(
                MySqlPacket(
                    sequence_id=raw[3],
                    payload=raw[4:],
                    raw=raw,
                )
            )

        return packets


def build_packet(payload: bytes, sequence_id: int) -> bytes:
    if len(payload) > MAX_PACKET_PAYLOAD:
        raise ValueError("Single MySQL packet payload is too large")
    if not 0 <= sequence_id <= 255:
        raise ValueError("MySQL sequence id must be between 0 and 255")

    return (
        len(payload).to_bytes(3, "little")
        + bytes([sequence_id])
        + payload
    )


def build_error_packet(
    message: str,
    *,
    sequence_id: int = 1,
    error_code: int = 1148,
    sql_state: str = "42000",
) -> bytes:
    if len(sql_state) != 5:
        raise ValueError("MySQL SQLSTATE must contain five characters")

    payload = (
        b"\xff"
        + error_code.to_bytes(2, "little")
        + b"#"
        + sql_state.encode("ascii")
        + message.encode("utf-8", errors="replace")
    )
    return build_packet(payload, sequence_id)


def parse_command(packet: MySqlPacket) -> tuple[int, bytes]:
    if not packet.payload:
        raise MySqlProtocolError("MySQL command packet is empty")
    return packet.payload[0], packet.payload[1:]


def parse_query(command_payload: bytes) -> str:
    if not command_payload:
        raise MySqlProtocolError("COM_QUERY contains no SQL text")
    try:
        return command_payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MySqlProtocolError(
            "COM_QUERY contains invalid UTF-8"
        ) from exc


def parse_database_name(command_payload: bytes) -> str:
    if not command_payload:
        raise MySqlProtocolError("COM_INIT_DB contains no database name")
    try:
        return command_payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MySqlProtocolError(
            "COM_INIT_DB contains invalid UTF-8"
        ) from exc
