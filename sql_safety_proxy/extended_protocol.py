"""Parses the extended query protocol messages (Parse/Bind/Execute) so we
can reconstruct what a client is actually about to execute - this is the
path most real drivers and ORMs use (asyncpg, psycopg2, JDBC, etc.), as
opposed to the Simple Query protocol that tools like psql use for ad hoc
`-c` commands.
"""
import struct
from dataclasses import dataclass, field
from typing import Optional


def _read_cstring(buf: bytes, offset: int) -> tuple[str, int]:
    end = buf.index(0, offset)
    return buf[offset:end].decode("utf8"), end + 1


@dataclass
class ParseMessage:
    statement_name: str
    query: str  # e.g. "UPDATE users SET active = $1 WHERE id = $2"


def parse_parse_message(payload: bytes) -> ParseMessage:
    statement_name, offset = _read_cstring(payload, 0)
    query, offset = _read_cstring(payload, offset)
    return ParseMessage(statement_name=statement_name, query=query)


@dataclass
class BindMessage:
    portal_name: str
    statement_name: str
    # One entry per parameter: raw bytes, or None for SQL NULL.
    param_values: list[Optional[bytes]] = field(default_factory=list)
    # 0 = text, 1 = binary, per Postgres protocol - see resolve_format_codes below.
    format_codes: list[int] = field(default_factory=list)


def parse_bind_message(payload: bytes) -> BindMessage:
    portal_name, offset = _read_cstring(payload, 0)
    statement_name, offset = _read_cstring(payload, offset)

    (num_format_codes,) = struct.unpack_from(">h", payload, offset)
    offset += 2
    raw_format_codes = list(struct.unpack_from(f">{num_format_codes}h", payload, offset)) if num_format_codes else []
    offset += 2 * num_format_codes

    (num_params,) = struct.unpack_from(">h", payload, offset)
    offset += 2
    values: list[Optional[bytes]] = []
    for _ in range(num_params):
        (length,) = struct.unpack_from(">i", payload, offset)
        offset += 4
        if length == -1:
            values.append(None)
        else:
            values.append(payload[offset:offset + length])
            offset += length

    return BindMessage(
        portal_name=portal_name,
        statement_name=statement_name,
        param_values=values,
        format_codes=resolve_format_codes(raw_format_codes, num_params),
    )


def resolve_format_codes(raw_format_codes: list[int], num_params: int) -> list[int]:
    """Per the Postgres protocol: zero codes means all-text, one code applies
    to every parameter, and N codes means one per parameter."""
    if len(raw_format_codes) == 0:
        return [0] * num_params
    if len(raw_format_codes) == 1:
        return raw_format_codes * num_params
    return raw_format_codes


@dataclass
class ExecuteMessage:
    portal_name: str
    max_rows: int


def parse_execute_message(payload: bytes) -> ExecuteMessage:
    portal_name, offset = _read_cstring(payload, 0)
    (max_rows,) = struct.unpack_from(">i", payload, offset)
    return ExecuteMessage(portal_name=portal_name, max_rows=max_rows)
