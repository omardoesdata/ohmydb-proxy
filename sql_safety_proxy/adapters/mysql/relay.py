"""In-memory MySQL client/backend relay orchestration."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from sql_safety_proxy.proxy import ProxyOptions

from .auth import (
    MySqlAuthPhase,
    MySqlAuthState,
)
from .backend import (
    MySqlBackendPhase,
    MySqlBackendState,
    route_backend_packet,
)
from .dispatcher import dispatch_authenticated_command
from .protocol import (
    DEFAULT_MAX_PACKET_BYTES,
    MySqlLogicalMessageAssembler,
    MySqlPacketFramer,
    MySqlProtocolError,
    build_error_packet,
    parse_handshake_response,
)
from .session import MySqlSessionState


MYSQL_TLS_ERROR_CODE = 3159
MYSQL_TLS_SQL_STATE = "HY000"


@dataclass
class MySqlRelayState:
    database: str
    max_packet_bytes: int = DEFAULT_MAX_PACKET_BYTES
    max_session_items: int = 256
    max_session_state_bytes: int = 8 * 1024 * 1024
    client_framer: MySqlPacketFramer = field(init=False)
    backend_framer: MySqlPacketFramer = field(init=False)
    command_assembler: MySqlLogicalMessageAssembler = field(
        init=False
    )
    auth: MySqlAuthState = field(init=False)
    session: MySqlSessionState = field(init=False)
    backend: MySqlBackendState = field(init=False)
    initial_backend_handshake_seen: bool = False

    def __post_init__(self) -> None:
        self.client_framer = MySqlPacketFramer(
            max_packet_bytes=self.max_packet_bytes
        )
        self.backend_framer = MySqlPacketFramer(
            max_packet_bytes=self.max_packet_bytes
        )
        self.command_assembler = MySqlLogicalMessageAssembler(
            max_message_bytes=self.max_packet_bytes
        )

        self.auth = MySqlAuthState(database=self.database)
        self.session = MySqlSessionState(
            database=self.database,
            max_prepared_statements=self.max_session_items,
            max_state_bytes=self.max_session_state_bytes,
        )
        self.backend = MySqlBackendState(
            auth=self.auth,
            session=self.session,
        )


async def process_backend_chunk(
    *,
    chunk: bytes,
    state: MySqlRelayState,
    client_writer: asyncio.StreamWriter,
) -> int:
    """Process bytes received from the MySQL backend.

    Returns the number of complete packets processed.
    """

    packets = state.backend_framer.push(chunk)

    for packet in packets:
        if not state.initial_backend_handshake_seen:
            client_writer.write(packet.raw)
            await client_writer.drain()
            state.initial_backend_handshake_seen = True
            continue

        await route_backend_packet(
            packet=packet,
            state=state.backend,
            client_writer=client_writer,
        )

    return len(packets)


async def process_client_chunk(
    *,
    chunk: bytes,
    state: MySqlRelayState,
    backend_writer: asyncio.StreamWriter,
    client_writer: asyncio.StreamWriter,
    opts: ProxyOptions,
) -> int:
    """Process bytes received from a MySQL client.

    Returns the number of complete packets processed.
    """

    packets = state.client_framer.push(chunk)

    for packet in packets:
        if not state.initial_backend_handshake_seen:
            raise MySqlProtocolError(
                "Client data arrived before the backend handshake"
            )

        if (
            state.auth.phase
            == MySqlAuthPhase.WAITING_FOR_CLIENT_RESPONSE
        ):
            response = parse_handshake_response(packet.payload)
            state.auth.accept_client_response(response)

            if response.is_ssl_request:
                client_writer.write(
                    build_error_packet(
                        state.auth.failure_reason
                        or "MySQL TLS is unsupported",
                        sequence_id=(packet.sequence_id + 1) % 256,
                        error_code=MYSQL_TLS_ERROR_CODE,
                        sql_state=MYSQL_TLS_SQL_STATE,
                    )
                )
                await client_writer.drain()
                state.backend.mark_closed()
                continue

            state.session.database = state.auth.database

            backend_writer.write(packet.raw)
            await backend_writer.drain()
            continue

        if (
            state.backend.phase
            == MySqlBackendPhase.AUTHENTICATION
        ):
            # Authentication switch and auth-more-data client replies are
            # opaque to the proxy and must be passed through unchanged.
            backend_writer.write(packet.raw)
            await backend_writer.drain()
            continue

        if (
            state.backend.phase
            == MySqlBackendPhase.CLOSED
        ):
            raise MySqlProtocolError(
                "Client packet received after MySQL connection closed"
            )

        message = state.command_assembler.push(packet)

        if message is None:
            continue

        await dispatch_authenticated_command(
            message=message,
            session=state.session,
            backend_writer=backend_writer,
            client_writer=client_writer,
            opts=opts,
        )

    return len(packets)
