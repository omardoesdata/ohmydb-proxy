"""MySQL packet framing and command helpers."""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from enum import Enum

MAX_PACKET_PAYLOAD = 0xFFFFFF
DEFAULT_MAX_PACKET_BYTES = 64 * 1024 * 1024

COM_QUIT = 0x01
COM_INIT_DB = 0x02
COM_QUERY = 0x03
COM_PING = 0x0E
COM_STMT_PREPARE = 0x16
COM_STMT_EXECUTE = 0x17
COM_STMT_SEND_LONG_DATA = 0x18
COM_STMT_CLOSE = 0x19
COM_STMT_RESET = 0x1A

MARIADB_STMT_ID_LAST = 0xFFFFFFFF

CLIENT_MYSQL = 0x00000001
CLIENT_CONNECT_WITH_DB = 0x00000008
CLIENT_SSL = 0x00000800
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_TRANSACTIONS = 0x00002000
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_PLUGIN_AUTH = 0x00080000
CLIENT_DEPRECATE_EOF = 0x01000000
MARIADB_CLIENT_CACHE_METADATA = 1 << 36

SERVER_STATUS_IN_TRANS = 0x0001
SERVER_STATUS_AUTOCOMMIT = 0x0002
SERVER_MORE_RESULTS_EXISTS = 0x0008
SERVER_STATUS_IN_TRANS_READONLY = 0x2000

MYSQL_TYPE_DECIMAL = 0x00
MYSQL_TYPE_TINY = 0x01
MYSQL_TYPE_SHORT = 0x02
MYSQL_TYPE_LONG = 0x03
MYSQL_TYPE_FLOAT = 0x04
MYSQL_TYPE_DOUBLE = 0x05
MYSQL_TYPE_NULL = 0x06
MYSQL_TYPE_TIMESTAMP = 0x07
MYSQL_TYPE_LONGLONG = 0x08
MYSQL_TYPE_INT24 = 0x09
MYSQL_TYPE_DATE = 0x0A
MYSQL_TYPE_TIME = 0x0B
MYSQL_TYPE_DATETIME = 0x0C
MYSQL_TYPE_YEAR = 0x0D
MYSQL_TYPE_NEWDATE = 0x0E
MYSQL_TYPE_VARCHAR = 0x0F
MYSQL_TYPE_BIT = 0x10
MYSQL_TYPE_TIMESTAMP2 = 0x11
MYSQL_TYPE_DATETIME2 = 0x12
MYSQL_TYPE_TIME2 = 0x13
MYSQL_TYPE_TYPED_ARRAY = 0x14
MYSQL_TYPE_VECTOR = 0xF2
MYSQL_TYPE_INVALID = 0xF3
MYSQL_TYPE_BOOL = 0xF4
MYSQL_TYPE_JSON = 0xF5
MYSQL_TYPE_NEWDECIMAL = 0xF6
MYSQL_TYPE_ENUM = 0xF7
MYSQL_TYPE_SET = 0xF8
MYSQL_TYPE_TINY_BLOB = 0xF9
MYSQL_TYPE_MEDIUM_BLOB = 0xFA
MYSQL_TYPE_LONG_BLOB = 0xFB
MYSQL_TYPE_BLOB = 0xFC
MYSQL_TYPE_VAR_STRING = 0xFD
MYSQL_TYPE_STRING = 0xFE
MYSQL_TYPE_GEOMETRY = 0xFF

MYSQL_UNSIGNED_FLAG = 0x80


class MySqlProtocolError(ValueError):
    """Raised when a MySQL packet is malformed or unsupported."""


class MySqlCommandKind(str, Enum):
    QUERY = "query"
    INIT_DB = "init_db"
    QUIT = "quit"
    PING = "ping"
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
class MySqlStmtLongData:
    statement_id: int
    parameter_id: int
    data: bytes


@dataclass(frozen=True)
class MySqlParameterType:
    type_code: int
    unsigned: bool = False


@dataclass(frozen=True)
class MySqlDecodedParameter:
    type_metadata: MySqlParameterType
    value: int | float | bytes | None
    sql_literal: str


@dataclass(frozen=True)
class MySqlStmtExecuteParameters:
    null_bitmap: bytes
    new_params_bound: bool
    parameter_types: tuple[MySqlParameterType, ...]
    parameters: tuple[MySqlDecodedParameter, ...]


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

    elif command_code == COM_PING:
        kind = MySqlCommandKind.PING

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


def parse_stmt_reset(command_payload: bytes) -> int:
    if len(command_payload) != 4:
        raise MySqlProtocolError(
            "COM_STMT_RESET payload must contain exactly its "
            "4-byte statement id"
        )

    return int.from_bytes(command_payload, "little")


def parse_ok_packet_status(
    payload: bytes,
    *,
    capability_flags: int,
) -> int:
    if not payload or payload[0] not in {0x00, 0xFE}:
        raise MySqlProtocolError("Backend packet is not an OK packet")

    offset = 1
    _, offset = _read_packet_length_encoded_integer(
        payload, offset, field_name="OK affected rows"
    )
    _, offset = _read_packet_length_encoded_integer(
        payload, offset, field_name="OK last insert id"
    )

    if capability_flags & CLIENT_PROTOCOL_41:
        status_end = offset + 2
        warnings_end = status_end + 2
        if warnings_end > len(payload):
            raise MySqlProtocolError(
                "Backend OK packet is missing status or warning fields"
            )
        return int.from_bytes(payload[offset:status_end], "little")

    if capability_flags & CLIENT_TRANSACTIONS:
        status_end = offset + 2
        if status_end > len(payload):
            raise MySqlProtocolError(
                "Backend OK packet is missing server status"
            )
        return int.from_bytes(payload[offset:status_end], "little")

    raise MySqlProtocolError(
        "Backend OK packet has no negotiated server-status field"
    )


def parse_eof_packet_status(
    payload: bytes,
    *,
    capability_flags: int,
) -> int:
    if not payload or payload[0] != 0xFE or len(payload) >= 9:
        raise MySqlProtocolError("Backend packet is not an EOF packet")
    if not capability_flags & CLIENT_PROTOCOL_41:
        raise MySqlProtocolError(
            "Backend EOF packet has no negotiated server-status field"
        )
    if len(payload) < 5:
        raise MySqlProtocolError(
            "Backend EOF packet is missing warning or status fields"
        )
    return int.from_bytes(payload[3:5], "little")


def parse_resultset_column_count(payload: bytes) -> int:
    count, _ = parse_resultset_header(payload, capability_flags=0)
    return count


def parse_resultset_header(
    payload: bytes,
    *,
    capability_flags: int,
) -> tuple[int, bool]:
    count, offset = _read_packet_length_encoded_integer(
        payload,
        0,
        field_name="result-set column count",
    )
    if count <= 0:
        raise MySqlProtocolError(
            "Backend result-set column count must be positive"
        )
    metadata_follows = True
    if capability_flags & MARIADB_CLIENT_CACHE_METADATA:
        if offset >= len(payload):
            raise MySqlProtocolError(
                "MariaDB result-set header is missing metadata indicator"
            )
        metadata_follows = payload[offset] == 1
        if payload[offset] not in {0, 1}:
            raise MySqlProtocolError(
                "MariaDB result-set metadata indicator must be 0 or 1"
            )
        offset += 1
    if offset != len(payload):
        raise MySqlProtocolError(
            "Backend result-set header has unexpected trailing bytes"
        )
    return count, metadata_follows


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


def parse_stmt_long_data(
    command_payload: bytes,
) -> MySqlStmtLongData:
    if len(command_payload) < 6:
        raise MySqlProtocolError(
            "COM_STMT_SEND_LONG_DATA payload is shorter than 6 bytes"
        )

    return MySqlStmtLongData(
        statement_id=int.from_bytes(command_payload[:4], "little"),
        parameter_id=int.from_bytes(command_payload[4:6], "little"),
        data=command_payload[6:],
    )


def parse_stmt_execute_parameters(
    execution: MySqlStmtExecute,
    *,
    parameter_count: int,
    previous_types: tuple[MySqlParameterType, ...] | None = None,
) -> MySqlStmtExecuteParameters:
    """Decode a COM_STMT_EXECUTE binary parameter payload strictly."""

    if parameter_count < 0:
        raise ValueError("parameter_count cannot be negative")

    if execution.iteration_count != 1:
        raise MySqlProtocolError(
            "COM_STMT_EXECUTE iteration count must be 1"
        )

    if execution.flags not in {0, 1, 2, 4}:
        raise MySqlProtocolError(
            "COM_STMT_EXECUTE contains unsupported cursor flags "
            f"0x{execution.flags:02X}"
        )

    payload = execution.parameter_payload
    if parameter_count == 0:
        if payload:
            raise MySqlProtocolError(
                "COM_STMT_EXECUTE without parameters contains trailing data"
            )
        return MySqlStmtExecuteParameters(
            null_bitmap=b"",
            new_params_bound=False,
            parameter_types=(),
            parameters=(),
        )

    null_bitmap_size = (parameter_count + 7) // 8
    minimum_size = null_bitmap_size + 1
    if len(payload) < minimum_size:
        raise MySqlProtocolError(
            "COM_STMT_EXECUTE parameter metadata is truncated"
        )

    null_bitmap = payload[:null_bitmap_size]
    offset = null_bitmap_size
    new_params_bound_flag = payload[offset]
    offset += 1

    if new_params_bound_flag not in {0, 1}:
        raise MySqlProtocolError(
            "COM_STMT_EXECUTE new_params_bound_flag must be 0 or 1"
        )

    if new_params_bound_flag:
        types_end = offset + (parameter_count * 2)
        if types_end > len(payload):
            raise MySqlProtocolError(
                "COM_STMT_EXECUTE parameter type metadata is truncated"
            )

        parameter_types = []
        for index in range(parameter_count):
            type_offset = offset + (index * 2)
            type_code = payload[type_offset]
            flags = payload[type_offset + 1]
            if flags & ~MYSQL_UNSIGNED_FLAG:
                raise MySqlProtocolError(
                    "COM_STMT_EXECUTE parameter type metadata contains "
                    f"unsupported flags for parameter {index}"
                )
            parameter_types.append(
                MySqlParameterType(
                    type_code=type_code,
                    unsigned=bool(flags & MYSQL_UNSIGNED_FLAG),
                )
            )
        types = tuple(parameter_types)
        offset = types_end

    else:
        if previous_types is None:
            raise MySqlProtocolError(
                "COM_STMT_EXECUTE reuses parameter types before metadata "
                "has been registered"
            )
        if len(previous_types) != parameter_count:
            raise MySqlProtocolError(
                "Stored COM_STMT_EXECUTE parameter metadata count does "
                "not match the prepared statement"
            )
        types = previous_types

    parameters: list[MySqlDecodedParameter] = []
    for index, type_metadata in enumerate(types):
        _validate_stmt_parameter_type(
            index=index,
            type_metadata=type_metadata,
        )
        is_null = bool(
            null_bitmap[index // 8] & (1 << (index % 8))
        )
        if is_null or type_metadata.type_code == MYSQL_TYPE_NULL:
            parameters.append(
                MySqlDecodedParameter(
                    type_metadata=type_metadata,
                    value=None,
                    sql_literal="NULL",
                )
            )
            continue

        parameter, offset = _decode_stmt_parameter(
            payload,
            offset,
            index=index,
            type_metadata=type_metadata,
        )
        parameters.append(parameter)

    if offset != len(payload):
        raise MySqlProtocolError(
            "COM_STMT_EXECUTE parameter payload contains trailing data"
        )

    return MySqlStmtExecuteParameters(
        null_bitmap=null_bitmap,
        new_params_bound=bool(new_params_bound_flag),
        parameter_types=types,
        parameters=tuple(parameters),
    )


def reconstruct_stmt_execute_sql(
    sql_template: str,
    parameters: tuple[MySqlDecodedParameter, ...],
) -> str:
    """Replace real MySQL placeholders without touching quoted text."""

    literals = iter(parameter.sql_literal for parameter in parameters)
    output: list[str] = []
    index = 0
    replacements = 0
    state = "sql"

    while index < len(sql_template):
        char = sql_template[index]
        following = (
            sql_template[index + 1]
            if index + 1 < len(sql_template)
            else ""
        )

        if state == "sql":
            if char == "?":
                try:
                    output.append(next(literals))
                except StopIteration as exc:
                    raise MySqlProtocolError(
                        "Prepared SQL contains more placeholders than "
                        "COM_STMT_PREPARE reported"
                    ) from exc
                replacements += 1
            elif char in {"'", '"', "`"}:
                state = char
                output.append(char)
            elif char == "#":
                state = "line_comment"
                output.append(char)
            elif char == "-" and following == "-" and (
                index + 2 == len(sql_template)
                or sql_template[index + 2].isspace()
            ):
                state = "line_comment"
                output.extend((char, following))
                index += 1
            elif char == "/" and following == "*":
                comment_prefix = sql_template[index:index + 4].upper()
                if comment_prefix.startswith("/*!") or (
                    comment_prefix == "/*M!"
                ):
                    raise MySqlProtocolError(
                        "Prepared SQL contains an executable comment and "
                        "cannot be reconstructed safely"
                    )
                state = "block_comment"
                output.extend((char, following))
                index += 1
            else:
                output.append(char)

        elif state in {"'", '"', "`"}:
            output.append(char)
            if char == "\\":
                raise MySqlProtocolError(
                    "Prepared SQL contains a mode-dependent backslash "
                    "escape and cannot be reconstructed safely"
                )
            if char == state:
                if following == state:
                    output.append(following)
                    index += 1
                else:
                    state = "sql"

        elif state == "line_comment":
            output.append(char)
            if char in {"\n", "\r"}:
                state = "sql"

        else:
            output.append(char)
            if char == "*" and following == "/":
                output.append(following)
                index += 1
                state = "sql"

        index += 1

    if state in {"'", '"', "`", "block_comment"}:
        raise MySqlProtocolError(
            "Prepared SQL has an unterminated quoted value or comment"
        )

    try:
        next(literals)
    except StopIteration:
        pass
    else:
        raise MySqlProtocolError(
            "Prepared SQL contains fewer placeholders than "
            "COM_STMT_PREPARE reported"
        )

    if replacements != len(parameters):
        raise MySqlProtocolError(
            "Prepared SQL placeholder count does not match parameter count"
        )

    return "".join(output)


def _decode_stmt_parameter(
    payload: bytes,
    offset: int,
    *,
    index: int,
    type_metadata: MySqlParameterType,
) -> tuple[MySqlDecodedParameter, int]:
    type_code = type_metadata.type_code

    integer_sizes = {
        MYSQL_TYPE_TINY: 1,
        MYSQL_TYPE_SHORT: 2,
        MYSQL_TYPE_LONG: 4,
        MYSQL_TYPE_LONGLONG: 8,
        MYSQL_TYPE_INT24: 4,
        MYSQL_TYPE_YEAR: 2,
    }
    if type_code in integer_sizes:
        size = integer_sizes[type_code]
        raw, offset = _take_stmt_bytes(
            payload, offset, size, index=index
        )
        value = int.from_bytes(
            raw,
            "little",
            signed=not type_metadata.unsigned,
        )
        return (
            MySqlDecodedParameter(
                type_metadata=type_metadata,
                value=value,
                sql_literal=str(value),
            ),
            offset,
        )

    if type_metadata.unsigned:
        raise MySqlProtocolError(
            "COM_STMT_EXECUTE unsigned flag is only supported for "
            f"integer parameter {index}"
        )

    if type_code in {MYSQL_TYPE_FLOAT, MYSQL_TYPE_DOUBLE}:
        size = 4 if type_code == MYSQL_TYPE_FLOAT else 8
        raw, offset = _take_stmt_bytes(
            payload, offset, size, index=index
        )
        value = struct.unpack("<f" if size == 4 else "<d", raw)[0]
        if not math.isfinite(value):
            raise MySqlProtocolError(
                "COM_STMT_EXECUTE floating-point parameter "
                f"{index} is not finite"
            )
        return (
            MySqlDecodedParameter(
                type_metadata=type_metadata,
                value=value,
                sql_literal=repr(value),
            ),
            offset,
        )

    if type_code in {
        MYSQL_TYPE_VARCHAR,
        MYSQL_TYPE_VAR_STRING,
        MYSQL_TYPE_STRING,
        MYSQL_TYPE_BIT,
    }:
        value, offset = _read_stmt_lenenc_bytes(
            payload, offset, index=index
        )
        return (
            MySqlDecodedParameter(
                type_metadata=type_metadata,
                value=value,
                sql_literal=f"X'{value.hex()}'",
            ),
            offset,
        )

    temporal_types = {
        MYSQL_TYPE_TIMESTAMP,
        MYSQL_TYPE_DATE,
        MYSQL_TYPE_TIME,
        MYSQL_TYPE_DATETIME,
        MYSQL_TYPE_NEWDATE,
        MYSQL_TYPE_TIMESTAMP2,
        MYSQL_TYPE_DATETIME2,
        MYSQL_TYPE_TIME2,
    }
    decimal_types = {MYSQL_TYPE_DECIMAL, MYSQL_TYPE_NEWDECIMAL}
    blob_types = {
        MYSQL_TYPE_TINY_BLOB,
        MYSQL_TYPE_MEDIUM_BLOB,
        MYSQL_TYPE_LONG_BLOB,
        MYSQL_TYPE_BLOB,
    }

    if type_code in temporal_types:
        family = "temporal"
    elif type_code in decimal_types:
        family = "decimal"
    elif type_code in blob_types:
        family = "blob"
    else:
        family = "unsupported"

    raise MySqlProtocolError(
        f"COM_STMT_EXECUTE {family} parameter type "
        f"0x{type_code:02X} is not safely inspectable for parameter {index}"
    )


def _validate_stmt_parameter_type(
    *,
    index: int,
    type_metadata: MySqlParameterType,
) -> None:
    type_code = type_metadata.type_code
    integer_types = {
        MYSQL_TYPE_TINY,
        MYSQL_TYPE_SHORT,
        MYSQL_TYPE_LONG,
        MYSQL_TYPE_LONGLONG,
        MYSQL_TYPE_INT24,
        MYSQL_TYPE_YEAR,
    }
    scalar_types = integer_types | {
        MYSQL_TYPE_FLOAT,
        MYSQL_TYPE_DOUBLE,
        MYSQL_TYPE_NULL,
        MYSQL_TYPE_VARCHAR,
        MYSQL_TYPE_VAR_STRING,
        MYSQL_TYPE_STRING,
        MYSQL_TYPE_BIT,
    }

    if type_metadata.unsigned and type_code not in integer_types:
        raise MySqlProtocolError(
            "COM_STMT_EXECUTE unsigned flag is only supported for "
            f"integer parameter {index}"
        )

    if type_code in scalar_types:
        return

    temporal_types = {
        MYSQL_TYPE_TIMESTAMP,
        MYSQL_TYPE_DATE,
        MYSQL_TYPE_TIME,
        MYSQL_TYPE_DATETIME,
        MYSQL_TYPE_NEWDATE,
        MYSQL_TYPE_TIMESTAMP2,
        MYSQL_TYPE_DATETIME2,
        MYSQL_TYPE_TIME2,
    }
    decimal_types = {MYSQL_TYPE_DECIMAL, MYSQL_TYPE_NEWDECIMAL}
    blob_types = {
        MYSQL_TYPE_TINY_BLOB,
        MYSQL_TYPE_MEDIUM_BLOB,
        MYSQL_TYPE_LONG_BLOB,
        MYSQL_TYPE_BLOB,
    }

    if type_code in temporal_types:
        family = "temporal"
    elif type_code in decimal_types:
        family = "decimal"
    elif type_code in blob_types:
        family = "blob"
    else:
        family = "unsupported"

    raise MySqlProtocolError(
        f"COM_STMT_EXECUTE {family} parameter type "
        f"0x{type_code:02X} is not safely inspectable for parameter {index}"
    )


def _take_stmt_bytes(
    payload: bytes,
    offset: int,
    size: int,
    *,
    index: int,
) -> tuple[bytes, int]:
    end = offset + size
    if end > len(payload):
        raise MySqlProtocolError(
            f"COM_STMT_EXECUTE parameter {index} is truncated"
        )
    return payload[offset:end], end


def _read_stmt_lenenc_bytes(
    payload: bytes,
    offset: int,
    *,
    index: int,
) -> tuple[bytes, int]:
    if offset >= len(payload):
        raise MySqlProtocolError(
            f"COM_STMT_EXECUTE parameter {index} is truncated"
        )

    marker = payload[offset]
    offset += 1
    if marker < 0xFB:
        size = marker
    elif marker == 0xFC:
        raw_size, offset = _take_stmt_bytes(
            payload, offset, 2, index=index
        )
        size = int.from_bytes(raw_size, "little")
    elif marker == 0xFD:
        raw_size, offset = _take_stmt_bytes(
            payload, offset, 3, index=index
        )
        size = int.from_bytes(raw_size, "little")
    elif marker == 0xFE:
        raw_size, offset = _take_stmt_bytes(
            payload, offset, 8, index=index
        )
        size = int.from_bytes(raw_size, "little")
    else:
        raise MySqlProtocolError(
            "COM_STMT_EXECUTE length-encoded parameter cannot use "
            f"marker 0x{marker:02X} for parameter {index}"
        )

    return _take_stmt_bytes(
        payload, offset, size, index=index
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


def _read_packet_length_encoded_integer(
    payload: bytes,
    offset: int,
    *,
    field_name: str,
) -> tuple[int, int]:
    if offset >= len(payload):
        raise MySqlProtocolError(
            f"Backend packet is missing {field_name}"
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
            f"Backend packet contains NULL for {field_name}"
        )

    end = offset + size
    if end > len(payload):
        raise MySqlProtocolError(
            f"Backend packet has truncated {field_name}"
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
    if not capability_flags & CLIENT_MYSQL:
        capability_flags |= (
            int.from_bytes(payload[28:32], "little") << 32
        )

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
