"""Routing for authenticated MySQL logical commands."""

from __future__ import annotations

import asyncio

from sql_safety_proxy.proxy import ProxyOptions

from .handler import (
    handle_mysql_protocol_gap,
    handle_mysql_query,
)
from .protocol import (
    MySqlCommandKind,
    MySqlLogicalMessage,
    MySqlProtocolError,
    parse_database_name,
    parse_logical_command,
)
from .session import MySqlSessionState


async def dispatch_authenticated_command(
    *,
    message: MySqlLogicalMessage,
    session: MySqlSessionState,
    backend_writer: asyncio.StreamWriter,
    client_writer: asyncio.StreamWriter,
    opts: ProxyOptions,
) -> bool:
    """Route one authenticated MySQL logical command.

    Returns True when the original command was forwarded.
    """

    response_sequence_id = (
        message.last_sequence_id + 1
    ) % 256

    try:
        command = parse_logical_command(message)
    except MySqlProtocolError as exc:
        return await handle_mysql_protocol_gap(
            reason=str(exc),
            command_code=None,
            raw_message=message.raw_packets,
            response_sequence_id=response_sequence_id,
            database=session.database,
            backend_writer=backend_writer,
            client_writer=client_writer,
            opts=opts,
        )

    if command.kind == MySqlCommandKind.QUERY:
        try:
            return await handle_mysql_query(
                message=message,
                command_payload=command.payload,
                database=session.database,
                backend_writer=backend_writer,
                client_writer=client_writer,
                opts=opts,
            )
        except MySqlProtocolError as exc:
            return await handle_mysql_protocol_gap(
                reason=str(exc),
                command_code=command.command_code,
                raw_message=message.raw_packets,
                response_sequence_id=response_sequence_id,
                database=session.database,
                backend_writer=backend_writer,
                client_writer=client_writer,
                opts=opts,
            )

    if command.kind == MySqlCommandKind.INIT_DB:
        try:
            database = parse_database_name(command.payload)
            session.begin_database_change(database)
        except MySqlProtocolError as exc:
            return await handle_mysql_protocol_gap(
                reason=str(exc),
                command_code=command.command_code,
                raw_message=message.raw_packets,
                response_sequence_id=response_sequence_id,
                database=session.database,
                backend_writer=backend_writer,
                client_writer=client_writer,
                opts=opts,
            )

        backend_writer.write(message.raw_packets)
        await backend_writer.drain()
        return True

    if command.kind == MySqlCommandKind.QUIT:
        session.mark_closing()
        backend_writer.write(message.raw_packets)
        await backend_writer.drain()
        return True

    if command.kind == MySqlCommandKind.PREPARED_STATEMENT:
        reason = (
            "MySQL binary prepared-statement commands are not "
            "implemented safely in v0.6"
        )
    else:
        reason = (
            "Unsupported MySQL command "
            f"0x{command.command_code:02X}"
        )

    return await handle_mysql_protocol_gap(
        reason=reason,
        command_code=command.command_code,
        raw_message=message.raw_packets,
        response_sequence_id=response_sequence_id,
        database=session.database,
        backend_writer=backend_writer,
        client_writer=client_writer,
        opts=opts,
    )
