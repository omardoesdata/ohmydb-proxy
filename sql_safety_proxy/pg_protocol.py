"""PostgreSQL frontend/backend wire-protocol framing helpers."""
from __future__ import annotations

import struct
from dataclasses import dataclass

SSL_REQUEST_CODE = 80877103
GSSENC_REQUEST_CODE = 80877104
DEFAULT_MAX_MESSAGE_BYTES = 64 * 1024 * 1024


class ProtocolMessageError(ValueError):
    """Raised when a PostgreSQL wire message is malformed or unsafe to parse."""


def is_negotiation_request(buf: bytes) -> bool:
    if len(buf) < 8:
        return False
    length, code = struct.unpack(">ii", buf[:8])
    return length == 8 and code in (SSL_REQUEST_CODE, GSSENC_REQUEST_CODE)


@dataclass(frozen=True)
class FrontendMessage:
    type: str
    payload: bytes
    raw: bytes


@dataclass(frozen=True)
class BackendMessage:
    type: str
    payload: bytes
    raw: bytes


class _MessageFramer:
    def __init__(self, max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES) -> None:
        if max_message_bytes < 5:
            raise ValueError("max_message_bytes must be at least 5")
        self._buffer = bytearray()
        self._max_message_bytes = max_message_bytes

    def _push(self, chunk: bytes, message_cls):
        self._buffer.extend(chunk)
        messages = []

        while True:
            if len(self._buffer) < 5:
                break

            length = struct.unpack(">i", self._buffer[1:5])[0]
            if length < 4:
                raise ProtocolMessageError(
                    f"invalid PostgreSQL message length {length}; minimum is 4"
                )

            total_size = 1 + length
            if total_size > self._max_message_bytes:
                raise ProtocolMessageError(
                    f"PostgreSQL message size {total_size} exceeds configured "
                    f"maximum {self._max_message_bytes}"
                )

            if len(self._buffer) < total_size:
                break

            raw = bytes(self._buffer[:total_size])
            del self._buffer[:total_size]
            try:
                msg_type = raw[:1].decode("ascii")
            except UnicodeDecodeError as exc:
                raise ProtocolMessageError("message type is not ASCII") from exc

            messages.append(
                message_cls(type=msg_type, payload=raw[5:], raw=raw)
            )

        return messages


class FrontendFramer(_MessageFramer):
    """Incrementally frame PostgreSQL frontend messages."""

    def push(self, chunk: bytes) -> list[FrontendMessage]:
        return self._push(chunk, FrontendMessage)


class BackendFramer(_MessageFramer):
    """Incrementally frame PostgreSQL backend messages."""

    def push(self, chunk: bytes) -> list[BackendMessage]:
        return self._push(chunk, BackendMessage)


def parse_simple_query_text(payload: bytes) -> str:
    if not payload or payload[-1] != 0:
        raise ProtocolMessageError("Simple Query payload is missing NUL terminator")
    try:
        return payload[:-1].decode("utf8")
    except UnicodeDecodeError as exc:
        raise ProtocolMessageError("Simple Query contains invalid UTF-8") from exc


def parse_startup_params(startup_message_raw: bytes) -> dict[str, str]:
    if len(startup_message_raw) < 9:
        raise ProtocolMessageError("StartupMessage is too short")

    declared_length = struct.unpack(">i", startup_message_raw[:4])[0]
    if declared_length != len(startup_message_raw):
        raise ProtocolMessageError(
            "StartupMessage declared length does not match received bytes"
        )

    offset = 8
    params: dict[str, str] = {}
    while offset < len(startup_message_raw):
        key_end = startup_message_raw.find(b"\x00", offset)
        if key_end == -1:
            raise ProtocolMessageError("StartupMessage key is not terminated")
        if key_end == offset:
            return params

        value_start = key_end + 1
        value_end = startup_message_raw.find(b"\x00", value_start)
        if value_end == -1:
            raise ProtocolMessageError("StartupMessage value is not terminated")

        try:
            key = startup_message_raw[offset:key_end].decode("utf8")
            value = startup_message_raw[value_start:value_end].decode("utf8")
        except UnicodeDecodeError as exc:
            raise ProtocolMessageError("StartupMessage contains invalid UTF-8") from exc

        params[key] = value
        offset = value_end + 1

    raise ProtocolMessageError("StartupMessage is missing final terminator")


def parse_ready_for_query_status(payload: bytes) -> str:
    if len(payload) != 1 or payload not in {b"I", b"T", b"E"}:
        raise ProtocolMessageError("ReadyForQuery has invalid transaction status")
    return payload.decode("ascii")


def build_error_response(message: str, sql_state: str = "42000") -> bytes:
    fields = (
        b"S" + b"ERROR\x00"
        + b"C" + sql_state.encode("utf8") + b"\x00"
        + b"M" + message.encode("utf8") + b"\x00"
    )
    body = fields + b"\x00"
    return b"E" + struct.pack(">i", len(body) + 4) + body


def build_ready_for_query(status: str = "I") -> bytes:
    if status not in {"I", "T", "E"}:
        raise ValueError("ReadyForQuery status must be I, T, or E")
    return b"Z" + struct.pack(">i", 5) + status.encode("ascii")
