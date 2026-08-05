"""MySQL packet framing and command helpers."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

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

CLIENT_CONNECT_WITH_DB = 0x00000008
CLIENT_SSL = 0x00000800
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_PLUGIN_AUTH = 0x00080000


class MySqlProtocolError(ValueError):
    """Raised when a MySQL packet is malformed or unsupported."""


class MySqlCommandKind(str, Enum):
    QUERY = "query"
    INIT_DB = "init_db"
    QUIT = "quit"
    STMT_PREPARE = "stmt_prepare"
    STMT_EXECUTE = "stmt_execute"
    STMT_SEND_LONG_DATA = "stmt_send_long_data"
    STMT_CLOSE = "stmt_close"
    STMT_RESET = "stmt_reset"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class MySqlCommand:
    command_code: int
    kind: MySqlCommandKind
    payload: bytes


@dataclass(frozen=True)
class MySqlPacket:
    sequence_id: int
    payload: bytes
    raw: bytes


@dataclass(frozen=True)
class MySqlHandshakeResponse:
    capability_flags: int
    username: str
    database: str | None
    auth_plugin: str | None
    is_ssl_request: bool


@dataclass(frozen=True)
class MySqlLogicalMessage:
    first_sequence_id: int
    last_sequence_id: int
    payload: bytes
    raw_packets: bytes
    packet_count: int


@dataclass(frozen=True)
class MySqlStmtExecute:
    statement_id: int
    flags: int
    iteration_count: int
    parameter_payload: bytes


@dataclass(frozen=True)
class MySqlStmtPrepareOk:
    statement_id: int
    column_count: int
    parameter_count: int
    warning_count: int


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


class MySqlLogicalMessageAssembler:
    def __init__(
        self,
        max_message_bytes: int = DEFAULT_MAX_PACKET_BYTES,
    ) -> None:
        if max_message_bytes < 1:
            raise ValueError("max_message_bytes must be positive")

        self._max_message_bytes = max_message_bytes
        self._payload_parts: list[bytes] = []
        self._raw_parts: list[bytes] = []
        self._first_sequence_id: int | None = None
        self._last_sequence_id: int | None = None
        self._packet_count = 0

    @property
    def has_partial_message(self) -> bool:
        return self._packet_count > 0

    def push(
        self,
        packet: MySqlPacket,
    ) -> MySqlLogicalMessage | None:
        if self._last_sequence_id is not None:
            expected = (self._last_sequence_id + 1) % 256
            if packet.sequence_id != expected:
                self.reset()
                raise MySqlProtocolError(
                    "MySQL logical-message packet sequence mismatch: "
                    f"expected {expected}, received {packet.sequence_id}"
                )

        if self._first_sequence_id is None:
            self._first_sequence_id = packet.sequence_id

        self._last_sequence_id = packet.sequence_id
        self._packet_count += 1
        self._payload_parts.append(packet.payload)
        self._raw_parts.append(packet.raw)

        total_payload = sum(len(part) for part in self._payload_parts)
        if total_payload > self._max_message_bytes:
            self.reset()
            raise MySqlProtocolError(
                "MySQL logical message exceeds configured maximum "
                f"{self._max_message_bytes}"
            )

        if len(packet.payload) == MAX_PACKET_PAYLOAD:
            return None

        message = MySqlLogicalMessage(
            first_sequence_id=self._first_sequence_id,
            last_sequence_id=self._last_sequence_id,
            payload=b"".join(self._payload_parts),
            raw_packets=b"".join(self._raw_parts),
            packet_count=self._packet_count,
        )
        self.reset()
        return message

    def reset(self) -> None:
        self._payload_parts = []
        self._raw_parts = []
        self._first_sequence_id = None
        self._last_sequence_id = None
        self._packet_count = 0


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


def classify_command(
    command_code: int,
    command_payload: bytes,
) -> MySqlCommand:
    if command_code == COM_QUERY:
        kind = MySqlCommandKind.QUERY

    elif command_code == COM_INIT_DB:
        kind = MySqlCommandKind.INIT_DB

    elif command_code == COM_QUIT:
        kind = MySqlCommandKind.QUIT

    elif command_code == COM_STMT_PREPARE:
        kind = MySqlCommandKind.STMT_PREPARE

    elif command_code == COM_STMT_EXECUTE:
        kind = MySqlCommandKind.STMT_EXECUTE

    elif command_code == COM_STMT_SEND_LONG_DATA:
        kind = MySqlCommandKind.STMT_SEND_LONG_DATA

    elif command_code == COM_STMT_CLOSE:
        kind = MySqlCommandKind.STMT_CLOSE

    elif command_code == COM_STMT_RESET:
        kind = MySqlCommandKind.STMT_RESET

    else:
        kind = MySqlCommandKind.UNSUPPORTED

    return MySqlCommand(
        command_code=command_code,
        kind=kind,
        payload=command_payload,
    )


def parse_logical_command(
    message: MySqlLogicalMessage,
) -> MySqlCommand:
    if not message.payload:
        raise MySqlProtocolError(
            "MySQL logical command message is empty"
        )

    return classify_command(
        message.payload[0],
        message.payload[1:],
    )


def parse_query(command_payload: bytes) -> str:
    if not command_payload:
        raise MySqlProtocolError("COM_QUERY contains no SQL text")
    try:
        return command_payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MySqlProtocolError(
            "COM_QUERY contains invalid UTF-8"
        ) from exc


def parse_stmt_prepare(
    command_payload: bytes,
) -> str:
    if not command_payload:
        raise MySqlProtocolError(
            "COM_STMT_PREPARE contains no SQL text"
        )

    try:
        return command_payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MySqlProtocolError(
            "COM_STMT_PREPARE contains invalid UTF-8"
        ) from exc


def parse_statement_id(command_payload: bytes) -> int:
    if len(command_payload) < 4:
        raise MySqlProtocolError(
            "MySQL prepared-statement command is missing "
            "its 4-byte statement id"
        )

    return int.from_bytes(
        command_payload[:4],
        "little",
    )


def parse_stmt_execute(
    command_payload: bytes,
) -> MySqlStmtExecute:
    if len(command_payload) < 9:
        raise MySqlProtocolError(
            "COM_STMT_EXECUTE payload is shorter than 9 bytes"
        )

    return MySqlStmtExecute(
        statement_id=int.from_bytes(
            command_payload[0:4],
            "little",
        ),
        flags=command_payload[4],
        iteration_count=int.from_bytes(
            command_payload[5:9],
            "little",
        ),
        parameter_payload=command_payload[9:],
    )


def parse_stmt_prepare_ok(
    backend_payload: bytes,
) -> MySqlStmtPrepareOk:
    if not backend_payload or backend_payload[0] != 0x00:
        raise MySqlProtocolError(
            "Backend packet is not COM_STMT_PREPARE_OK"
        )

    if len(backend_payload) < 12:
        raise MySqlProtocolError(
            "COM_STMT_PREPARE_OK packet is shorter than 12 bytes"
        )

    return MySqlStmtPrepareOk(
        statement_id=int.from_bytes(
            backend_payload[1:5],
            "little",
        ),
        column_count=int.from_bytes(
            backend_payload[5:7],
            "little",
        ),
        parameter_count=int.from_bytes(
            backend_payload[7:9],
            "little",
        ),
        warning_count=int.from_bytes(
            backend_payload[10:12],
            "little",
        ),
    )


def parse_database_name(command_payload: bytes) -> str:
    if not command_payload:
        raise MySqlProtocolError("COM_INIT_DB contains no database name")
    try:
        return command_payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MySqlProtocolError(
            "COM_INIT_DB contains invalid UTF-8"
        ) from exc


def _read_null_terminated(
    payload: bytes,
    offset: int,
    *,
    field_name: str,
) -> tuple[bytes, int]:
    end = payload.find(b"\x00", offset)
    if end < 0:
        raise MySqlProtocolError(
            f"MySQL handshake response {field_name} is not null terminated"
        )
    return payload[offset:end], end + 1


def _read_length_encoded_integer(
    payload: bytes,
    offset: int,
) -> tuple[int, int]:
    if offset >= len(payload):
        raise MySqlProtocolError(
            "MySQL handshake response is missing a length-encoded integer"
        )

    first = payload[offset]
    offset += 1

    if first < 0xFB:
        return first, offset

    if first == 0xFC:
        size = 2
    elif first == 0xFD:
        size = 3
    elif first == 0xFE:
        size = 8
    else:
        raise MySqlProtocolError(
            "Unsupported NULL length-encoded value in handshake response"
        )

    end = offset + size
    if end > len(payload):
        raise MySqlProtocolError(
            "Truncated length-encoded integer in handshake response"
        )

    return int.from_bytes(payload[offset:end], "little"), end


def parse_handshake_response(
    payload: bytes,
) -> MySqlHandshakeResponse:
    if len(payload) < 32:
        raise MySqlProtocolError(
            "MySQL handshake response is shorter than 32 bytes"
        )

    capability_flags = int.from_bytes(payload[0:4], "little")

    if capability_flags & CLIENT_SSL and len(payload) == 32:
        return MySqlHandshakeResponse(
            capability_flags=capability_flags,
            username="",
            database=None,
            auth_plugin=None,
            is_ssl_request=True,
        )

    offset = 32

    username_bytes, offset = _read_null_terminated(
        payload,
        offset,
        field_name="username",
    )

    try:
        username = username_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MySqlProtocolError(
            "MySQL handshake response username is not valid UTF-8"
        ) from exc

    if capability_flags & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
        auth_length, offset = _read_length_encoded_integer(
            payload,
            offset,
        )
        offset += auth_length

    elif capability_flags & CLIENT_SECURE_CONNECTION:
        if offset >= len(payload):
            raise MySqlProtocolError(
                "MySQL handshake response is missing auth-response length"
            )
        auth_length = payload[offset]
        offset += 1 + auth_length

    else:
        _, offset = _read_null_terminated(
            payload,
            offset,
            field_name="auth response",
        )

    if offset > len(payload):
        raise MySqlProtocolError(
            "MySQL handshake response auth data is truncated"
        )

    database = None
    if capability_flags & CLIENT_CONNECT_WITH_DB:
        database_bytes, offset = _read_null_terminated(
            payload,
            offset,
            field_name="database",
        )
        try:
            database = database_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise MySqlProtocolError(
                "MySQL handshake response database is not valid UTF-8"
            ) from exc

    auth_plugin = None
    if capability_flags & CLIENT_PLUGIN_AUTH and offset < len(payload):
        plugin_bytes, offset = _read_null_terminated(
            payload,
            offset,
            field_name="auth plugin",
        )
        try:
            auth_plugin = plugin_bytes.decode("ascii")
        except UnicodeDecodeError as exc:
            raise MySqlProtocolError(
                "MySQL handshake response auth plugin is not ASCII"
            ) from exc

    return MySqlHandshakeResponse(
        capability_flags=capability_flags,
        username=username,
        database=database,
        auth_plugin=auth_plugin,
        is_ssl_request=False,
    )
