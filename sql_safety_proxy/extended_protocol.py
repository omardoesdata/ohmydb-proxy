"""Strict parsers for PostgreSQL extended-query protocol messages."""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from .pg_protocol import ProtocolMessageError


def _require(buf: bytes, offset: int, size: int, context: str) -> None:
    if size < 0 or offset < 0 or offset + size > len(buf):
        raise ProtocolMessageError(f"{context} is truncated")


def _read_cstring(buf: bytes, offset: int) -> tuple[str, int]:
    if offset < 0 or offset >= len(buf):
        raise ProtocolMessageError("missing NUL-terminated string")
    end = buf.find(b"\x00", offset)
    if end == -1:
        raise ProtocolMessageError("unterminated protocol string")
    try:
        value = buf[offset:end].decode("utf8")
    except UnicodeDecodeError as exc:
        raise ProtocolMessageError("protocol string contains invalid UTF-8") from exc
    return value, end + 1


def _read_int16(buf: bytes, offset: int, context: str) -> tuple[int, int]:
    _require(buf, offset, 2, context)
    return struct.unpack_from(">h", buf, offset)[0], offset + 2


def _read_int32(buf: bytes, offset: int, context: str) -> tuple[int, int]:
    _require(buf, offset, 4, context)
    return struct.unpack_from(">i", buf, offset)[0], offset + 4


@dataclass(frozen=True)
class ParseMessage:
    statement_name: str
    query: str


def parse_parse_message(payload: bytes) -> ParseMessage:
    statement_name, offset = _read_cstring(payload, 0)
    query, offset = _read_cstring(payload, offset)
    count, offset = _read_int16(payload, offset, "Parse parameter type count")
    if count < 0:
        raise ProtocolMessageError("Parse parameter type count cannot be negative")
    _require(payload, offset, count * 4, "Parse parameter OID list")
    offset += count * 4
    if offset != len(payload):
        raise ProtocolMessageError("Parse message contains trailing bytes")
    return ParseMessage(statement_name=statement_name, query=query)


@dataclass(frozen=True)
class BindMessage:
    portal_name: str
    statement_name: str
    param_values: list[Optional[bytes]] = field(default_factory=list)
    format_codes: list[int] = field(default_factory=list)
    result_format_codes: list[int] = field(default_factory=list)


def parse_bind_message(payload: bytes) -> BindMessage:
    portal_name, offset = _read_cstring(payload, 0)
    statement_name, offset = _read_cstring(payload, offset)

    num_format_codes, offset = _read_int16(payload, offset, "Bind format count")
    if num_format_codes < 0:
        raise ProtocolMessageError("Bind format count cannot be negative")
    _require(payload, offset, num_format_codes * 2, "Bind format codes")
    raw_format_codes = list(
        struct.unpack_from(f">{num_format_codes}h", payload, offset)
    ) if num_format_codes else []
    offset += num_format_codes * 2
    if any(code not in (0, 1) for code in raw_format_codes):
        raise ProtocolMessageError("Bind parameter format code must be 0 or 1")

    num_params, offset = _read_int16(payload, offset, "Bind parameter count")
    if num_params < 0:
        raise ProtocolMessageError("Bind parameter count cannot be negative")

    values: list[Optional[bytes]] = []
    for _ in range(num_params):
        length, offset = _read_int32(payload, offset, "Bind parameter length")
        if length == -1:
            values.append(None)
            continue
        if length < -1:
            raise ProtocolMessageError("Bind parameter length is invalid")
        _require(payload, offset, length, "Bind parameter value")
        values.append(payload[offset:offset + length])
        offset += length

    num_result_codes, offset = _read_int16(payload, offset, "Bind result format count")
    if num_result_codes < 0:
        raise ProtocolMessageError("Bind result format count cannot be negative")
    _require(payload, offset, num_result_codes * 2, "Bind result format codes")
    result_codes = list(
        struct.unpack_from(f">{num_result_codes}h", payload, offset)
    ) if num_result_codes else []
    offset += num_result_codes * 2
    if any(code not in (0, 1) for code in result_codes):
        raise ProtocolMessageError("Bind result format code must be 0 or 1")
    if offset != len(payload):
        raise ProtocolMessageError("Bind message contains trailing bytes")

    return BindMessage(
        portal_name=portal_name,
        statement_name=statement_name,
        param_values=values,
        format_codes=resolve_format_codes(raw_format_codes, num_params),
        result_format_codes=result_codes,
    )


def resolve_format_codes(raw_format_codes: list[int], num_params: int) -> list[int]:
    if len(raw_format_codes) == 0:
        return [0] * num_params
    if len(raw_format_codes) == 1:
        return raw_format_codes * num_params
    if len(raw_format_codes) != num_params:
        raise ProtocolMessageError(
            "Bind format code count must be zero, one, or match parameter count"
        )
    return raw_format_codes


@dataclass(frozen=True)
class ExecuteMessage:
    portal_name: str
    max_rows: int


def parse_execute_message(payload: bytes) -> ExecuteMessage:
    portal_name, offset = _read_cstring(payload, 0)
    max_rows, offset = _read_int32(payload, offset, "Execute max rows")
    if max_rows < 0:
        raise ProtocolMessageError("Execute max rows cannot be negative")
    if offset != len(payload):
        raise ProtocolMessageError("Execute message contains trailing bytes")
    return ExecuteMessage(portal_name=portal_name, max_rows=max_rows)


@dataclass(frozen=True)
class CloseMessage:
    target_type: str
    name: str


def parse_close_message(payload: bytes) -> CloseMessage:
    if not payload:
        raise ProtocolMessageError("Close message is empty")
    try:
        target_type = payload[:1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProtocolMessageError("Close target type is not ASCII") from exc
    if target_type not in {"S", "P"}:
        raise ProtocolMessageError("Close target type must be S or P")
    name, offset = _read_cstring(payload, 1)
    if offset != len(payload):
        raise ProtocolMessageError("Close message contains trailing bytes")
    return CloseMessage(target_type=target_type, name=name)
