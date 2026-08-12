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
    CLIENT_DEPRECATE_EOF,
    CLIENT_PROTOCOL_41,
    CLIENT_TRANSACTIONS,
    MySqlPacket,
    MySqlProtocolError,
    parse_ok_packet_status,
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


def _update_transaction_status_from_ok(
    state: MySqlBackendState,
    payload: bytes,
) -> None:
    if not state.auth.capability_flags & (
        CLIENT_PROTOCOL_41 | CLIENT_TRANSACTIONS
    ):
        return
    state.session.update_transaction_status(
        parse_ok_packet_status(
            payload,
            capability_flags=state.auth.capability_flags,
        )
    )


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
            _update_transaction_status_from_ok(state, packet.payload)
            state.mark_authenticated()

        elif packet_type == MySqlBackendAuthPacket.ERROR:
            state.mark_closed()

        return packet_type

    finish_prepare_after_forward = False
    fail_prepare_after_forward = False

    if state.session.pending_ping:
        state.session.complete_ping(packet.payload)
        if packet.payload and packet.payload[0] == 0x00:
            _update_transaction_status_from_ok(state, packet.payload)

    elif state.session.pending_statement_reset_id is not None:
        state.session.complete_statement_reset(packet.payload)
        if packet.payload and packet.payload[0] == 0x00:
            _update_transaction_status_from_ok(state, packet.payload)

    elif state.session.pending_database is not None:
        state.session.complete_database_change(packet.payload)
        if packet.payload and packet.payload[0] == 0x00:
            _update_transaction_status_from_ok(state, packet.payload)

    elif state.session.pending_statement_sql is not None:
        if state.session.pending_prepared_statement_id is not None:
            if packet.payload and packet.payload[0] == 0xFF:
                fail_prepare_after_forward = True
            else:
                try:
                    finish_prepare_after_forward = (
                        state.session.consume_statement_prepare_metadata(
                            packet.payload,
                            capability_flags=state.auth.capability_flags,
                        )
                    )
                except MySqlProtocolError:
                    state.session.fail_statement_prepare()
                    raise

        elif packet.payload and packet.payload[0] == 0x00:
            prepared = parse_stmt_prepare_ok(packet.payload)
            state.session.accept_statement_prepare_ok(
                statement_id=prepared.statement_id,
                parameter_count=prepared.parameter_count,
                column_count=prepared.column_count,
                deprecate_eof=bool(
                    state.auth.capability_flags
                    & CLIENT_DEPRECATE_EOF
                ),
            )
            finish_prepare_after_forward = (
                state.session.pending_prepare_metadata_packets == 0
            )

        elif packet.payload and packet.payload[0] == 0xFF:
            fail_prepare_after_forward = True

        else:
            state.session.fail_statement_prepare()
            raise MySqlProtocolError(
                "Unexpected backend response to COM_STMT_PREPARE"
            )

    elif state.session.pending_command_response is not None:
        state.session.accept_command_response_packet(
            packet.payload,
            capability_flags=state.auth.capability_flags,
        )

    client_writer.write(packet.raw)
    await client_writer.drain()

    if finish_prepare_after_forward:
        state.session.finish_statement_prepare_response()
    elif fail_prepare_after_forward:
        state.session.fail_statement_prepare()
    return None
