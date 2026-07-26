"""Decodes a bound parameter's raw wire bytes into a SQL literal we can
substitute directly into a preview query (e.g. `id = 42` or `name = 'bob'`).

Text-format (format code 0) parameters are decoded exactly - the bytes are
just the literal text Postgres itself would parse, so we can substitute
them as a quoted string literal and let Postgres's normal implicit casting
handle the rest.

Binary-format (format code 1) parameters are trickier: the wire protocol
does not hand us the parameter's Postgres type OID directly (that comes
from a separate ParameterDescription message we don't currently parse), so
we fall back to a byte-length heuristic for the common scalar types. This
is a real limitation, not a hidden one - see `confidence` on the result.
"""
import struct
from dataclasses import dataclass
from typing import Optional


@dataclass
class DecodedParam:
    sql_literal: str
    confidence: str  # "exact" (text format) | "heuristic" (binary, length-guessed) | "unknown" (couldn't decode)


def decode_param(raw: Optional[bytes], format_code: int) -> DecodedParam:
    if raw is None:
        return DecodedParam("NULL", "exact")

    if format_code == 0:  # text format - unambiguous, it's just the literal text
        text = raw.decode("utf8", errors="replace")
        return DecodedParam(_quote(text), "exact")

    # Binary format: guess by byte length, since we don't know the real type OID.
    length = len(raw)
    if length == 1:
        return DecodedParam("TRUE" if raw[0] != 0 else "FALSE", "heuristic")
    if length == 2:
        (val,) = struct.unpack(">h", raw)
        return DecodedParam(str(val), "heuristic")
    if length == 4:
        (val,) = struct.unpack(">i", raw)  # assumes int4 over float4 - the common case for WHERE-clause comparisons
        return DecodedParam(str(val), "heuristic")
    if length == 8:
        (val,) = struct.unpack(">q", raw)  # assumes int8 over float8/timestamp
        return DecodedParam(str(val), "heuristic")

    try:
        text = raw.decode("utf8")
        return DecodedParam(_quote(text), "heuristic")
    except UnicodeDecodeError:
        return DecodedParam("NULL", "unknown")  # genuinely can't decode - caller should treat estimate as unavailable


def _quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"
