"""Minimal Postgres frontend/backend wire protocol helpers - just enough to
detect SSL negotiation, frame frontend messages after startup, read the SQL
text out of a Simple Query message, and synthesize an ErrorResponse when we
need to block a query ourselves.
"""
import struct
from dataclasses import dataclass
from typing import Optional

SSL_REQUEST_CODE = 80877103
GSSENC_REQUEST_CODE = 80877104


def is_negotiation_request(buf: bytes) -> bool:
    if len(buf) < 8:
        return False
    length, code = struct.unpack(">ii", buf[:8])
    return length == 8 and code in (SSL_REQUEST_CODE, GSSENC_REQUEST_CODE)


@dataclass
class FrontendMessage:
    type: str  # single character, e.g. 'Q', 'P', 'p', 'X'
    payload: bytes
    raw: bytes  # forward this unchanged when the message is safe to pass through


class FrontendFramer:
    """Incrementally frames a byte stream into discrete frontend messages."""

    def __init__(self) -> None:
        self._buffer = b""

    def push(self, chunk: bytes) -> list[FrontendMessage]:
        self._buffer += chunk
        messages: list[FrontendMessage] = []

        while True:
            if len(self._buffer) < 5:
                break  # need at least type(1) + length(4)
            msg_type = chr(self._buffer[0])
            (length,) = struct.unpack(">i", self._buffer[1:5])  # includes itself, not the type byte
            total_size = 1 + length
            if len(self._buffer) < total_size:
                break  # wait for more data

            raw = self._buffer[:total_size]
            payload = self._buffer[5:total_size]
            messages.append(FrontendMessage(type=msg_type, payload=payload, raw=raw))
            self._buffer = self._buffer[total_size:]

        return messages


def parse_simple_query_text(payload: bytes) -> str:
    null_idx = payload.find(b"\x00")
    return payload[: null_idx if null_idx != -1 else None].decode("utf8")


def parse_startup_params(startup_message_raw: bytes) -> dict[str, str]:
    # StartupMessage: [int32 length][int32 protocolVersion][key\0value\0]*[\0]
    offset = 8  # skip length + protocol version
    params: dict[str, str] = {}
    while offset < len(startup_message_raw):
        key_end = startup_message_raw.find(b"\x00", offset)
        if key_end == -1 or key_end == offset:
            break
        key = startup_message_raw[offset:key_end].decode("utf8")
        offset = key_end + 1
        val_end = startup_message_raw.find(b"\x00", offset)
        value = startup_message_raw[offset:val_end].decode("utf8")
        offset = val_end + 1
        params[key] = value
    return params


def build_error_response(message: str, sql_state: str = "42000") -> bytes:
    fields = (
        b"S" + b"ERROR\x00"
        + b"C" + sql_state.encode("utf8") + b"\x00"
        + b"M" + message.encode("utf8") + b"\x00"
    )
    body = fields + b"\x00"
    return b"E" + struct.pack(">i", len(body) + 4) + body


def build_ready_for_query(status: str = "I") -> bytes:
    return b"Z" + struct.pack(">i", 5) + status.encode("utf8")
