"""Backend packet routing for MySQL authentication and session state."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import Enum

from .auth import (
    MySqlAuthState,
    MySqlBackendAuthPacket,
)
from .protocol import (
    MySqlPacket,
    MySqlProtocolError,
    parse_stmt_prepare_ok,
)
from .session import MySqlSessionState


class MySqlBackendPhase(str, Enum):
    AUTHENTICATION = "authentication"
    COMMAND_RESPONSE = "command_response"
    CLOSED = "closed"


@dataclass
class MySqlBackendState:
    auth: MySqlAuthState
    session: MySqlSessionState
    phase: MySqlBackendPhase = (
        MySqlBackendPhase.AUTHENTICATION
    )

    def mark_authenticated(self) -> None:
        if not self.auth.authenticated:
            raise MySqlProtocolError(
                "Cannot enter command-response phase before "
                "MySQL authentication succeeds"
            )

        self.phase = MySqlBackendPhase.COMMAND_RESPONSE

    def mark_closed(self) -> None:
        self.phase = MySqlBackendPhase.CLOSED


async def route_backend_packet(
    *,
    packet: MySqlPacket,
    state: MySqlBackendState,
    client_writer: asyncio.StreamWriter,
) -> MySqlBackendAuthPacket | None:
    """Route one backend packet to the client and update state."""

    if state.phase == MySqlBackendPhase.CLOSED:
        raise MySqlProtocolError(
            "Backend packet received after MySQL connection closed"
        )

    if state.phase == MySqlBackendPhase.AUTHENTICATION:
        packet_type = state.auth.accept_backend_packet(packet)

        client_writer.write(packet.raw)
        await client_writer.drain()

        if packet_type == MySqlBackendAuthPacket.OK:
            state.mark_authenticated()

        elif packet_type == MySqlBackendAuthPacket.ERROR:
            state.mark_closed()

        return packet_type

    if state.session.pending_database is not None:
        state.session.complete_database_change(packet.payload)

    elif state.session.pending_statement_sql is not None:
        if packet.payload and packet.payload[0] == 0x00:
            prepared = parse_stmt_prepare_ok(packet.payload)
            state.session.complete_statement_prepare(
                statement_id=prepared.statement_id,
                parameter_count=prepared.parameter_count,
                column_count=prepared.column_count,
            )

        elif packet.payload and packet.payload[0] == 0xFF:
            state.session.fail_statement_prepare()

        else:
            state.session.fail_statement_prepare()
            raise MySqlProtocolError(
                "Unexpected backend response to COM_STMT_PREPARE"
            )

    client_writer.write(packet.raw)
    await client_writer.drain()
    return None
