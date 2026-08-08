"""Routing for authenticated MySQL logical commands."""

from __future__ import annotations

import asyncio

from sql_safety_proxy.proxy import ProxyOptions

from .handler import (
    handle_mysql_protocol_gap,
    handle_mysql_query,
    handle_mysql_stmt_execute,
)
from .protocol import (
    MARIADB_STMT_ID_LAST,
    MySqlCommandKind,
    MySqlLogicalMessage,
    MySqlProtocolError,
    build_error_packet,
    parse_database_name,
    parse_logical_command,
    parse_statement_id,
    parse_stmt_reset,
    parse_stmt_execute,
    parse_stmt_execute_parameters,
    parse_stmt_long_data,
    parse_stmt_prepare,
    reconstruct_stmt_execute_sql,
)
from .session import MySqlSessionState


async def _block_protocol_state_error(
    *,
    reason: str,
    response_sequence_id: int,
    client_writer: asyncio.StreamWriter,
) -> bool:
    client_writer.write(
        build_error_packet(
            (
                "Query blocked by sql-safety-proxy. Protocol state error: "
                f"{reason}."
            ),
            sequence_id=response_sequence_id,
            error_code=1148,
            sql_state="42000",
        )
    )
    await client_writer.drain()
    return False


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

    pipelined_execute = (
        command.kind == MySqlCommandKind.STMT_EXECUTE
        and len(command.payload) >= 4
        and int.from_bytes(command.payload[:4], "little")
        == MARIADB_STMT_ID_LAST
        and session.pending_statement_sql is not None
    )
    if (
        session.has_pending_lifecycle_operation
        and command.kind != MySqlCommandKind.QUIT
        and not pipelined_execute
    ):
        return await _block_protocol_state_error(
            reason=(
                "A MySQL command cannot run while a prior command "
                "acknowledgment is pending"
            ),
            response_sequence_id=response_sequence_id,
            client_writer=client_writer,
        )

    if command.kind == MySqlCommandKind.QUERY:
        try:
            session.begin_command_response("query")
        except MySqlProtocolError as exc:
            return await _block_protocol_state_error(
                reason=str(exc),
                response_sequence_id=response_sequence_id,
                client_writer=client_writer,
            )
        try:
            forwarded = await handle_mysql_query(
                message=message,
                command_payload=command.payload,
                database=session.database,
                backend_writer=backend_writer,
                client_writer=client_writer,
                opts=opts,
            )
        except MySqlProtocolError as exc:
            session.fail_command_forward()
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
        except BaseException:
            session.fail_command_forward()
            raise
        if not forwarded:
            session.fail_command_forward()
        return forwarded

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

    if command.kind == MySqlCommandKind.PING:
        if command.payload:
            return await _block_protocol_state_error(
                reason="COM_PING payload must be empty",
                response_sequence_id=response_sequence_id,
                client_writer=client_writer,
            )
        try:
            session.begin_ping()
            backend_writer.write(message.raw_packets)
            await backend_writer.drain()
        except MySqlProtocolError as exc:
            return await _block_protocol_state_error(
                reason=str(exc),
                response_sequence_id=response_sequence_id,
                client_writer=client_writer,
            )
        except BaseException:
            session.fail_ping()
            raise
        return True

    if command.kind == MySqlCommandKind.STMT_PREPARE:
        try:
            sql = parse_stmt_prepare(command.payload)
            session.begin_statement_prepare(sql)
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

    if command.kind == MySqlCommandKind.STMT_CLOSE:
        if session.has_pending_lifecycle_operation:
            return await _block_protocol_state_error(
                reason=(
                    "COM_STMT_CLOSE cannot run while a MySQL command "
                    "acknowledgment is pending"
                ),
                response_sequence_id=response_sequence_id,
                client_writer=client_writer,
            )
        try:
            statement_id = parse_statement_id(
                command.payload
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

        session.close_prepared_statement(statement_id)
        backend_writer.write(message.raw_packets)
        await backend_writer.drain()
        return True

    if command.kind == MySqlCommandKind.STMT_EXECUTE:
        try:
            execution = parse_stmt_execute(command.payload)
            if execution.statement_id == MARIADB_STMT_ID_LAST:
                if session.pending_statement_sql is not None:
                    event = session.pending_prepare_event
                    if event is None:
                        raise MySqlProtocolError(
                            "Pipelined COM_STMT_EXECUTE has no prepare event"
                        )
                    statement = await session.wait_for_statement_prepare(
                        event
                    )
                    if statement is None:
                        return await _block_protocol_state_error(
                            reason=(
                                "Pipelined COM_STMT_EXECUTE follows a failed "
                                "COM_STMT_PREPARE"
                            ),
                            response_sequence_id=response_sequence_id,
                            client_writer=client_writer,
                        )
                else:
                    statement = session.get_last_prepared_statement()
            else:
                statement = session.get_prepared_statement(
                    execution.statement_id
                )

            if statement.long_data_parameters:
                parameters = ", ".join(
                    str(index)
                    for index in sorted(
                        statement.long_data_parameters
                    )
                )
                raise MySqlProtocolError(
                    "COM_STMT_EXECUTE references uninspectable long-data "
                    f"parameters: {parameters}"
                )

            decoded = parse_stmt_execute_parameters(
                execution,
                parameter_count=statement.parameter_count,
                previous_types=statement.parameter_types,
            )
            inspection_sql = reconstruct_stmt_execute_sql(
                statement.sql,
                decoded.parameters,
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

        try:
            session.begin_command_response("stmt_execute")
            forwarded = await handle_mysql_stmt_execute(
                message=message,
                inspection_sql=inspection_sql,
                sql_description=(
                    "MYSQL_PREPARED_STATEMENT_"
                    f"{statement.statement_id}"
                ),
                estimate_safe=all(
                    not isinstance(parameter.value, bytes)
                    for parameter in decoded.parameters
                ),
                database=session.database,
                backend_writer=backend_writer,
                client_writer=client_writer,
                opts=opts,
            )
        except BaseException:
            session.fail_command_forward()
            raise

        if forwarded:
            session.register_statement_parameter_types(
                statement.statement_id,
                decoded.parameter_types,
            )
        else:
            session.fail_command_forward()
        return forwarded

    if command.kind == MySqlCommandKind.STMT_SEND_LONG_DATA:
        try:
            long_data = parse_stmt_long_data(command.payload)
            statement = session.get_prepared_statement(
                long_data.statement_id
            )
            if long_data.parameter_id >= statement.parameter_count:
                raise MySqlProtocolError(
                    "COM_STMT_SEND_LONG_DATA references out-of-range "
                    f"parameter {long_data.parameter_id}"
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

        forwarded = await handle_mysql_protocol_gap(
            reason=(
                "COM_STMT_SEND_LONG_DATA values cannot be inspected "
                "before prepared-statement execution"
            ),
            command_code=command.command_code,
            raw_message=message.raw_packets,
            response_sequence_id=response_sequence_id,
            database=session.database,
            backend_writer=backend_writer,
            client_writer=client_writer,
            opts=opts,
        )
        if forwarded:
            session.mark_statement_long_data(
                long_data.statement_id,
                long_data.parameter_id,
            )
        return forwarded

    if command.kind == MySqlCommandKind.STMT_RESET:
        try:
            statement_id = parse_stmt_reset(command.payload)
            session.begin_statement_reset(statement_id)
            backend_writer.write(message.raw_packets)
            await backend_writer.drain()
        except MySqlProtocolError as exc:
            return await _block_protocol_state_error(
                reason=str(exc),
                response_sequence_id=response_sequence_id,
                client_writer=client_writer,
            )
        except BaseException:
            session.fail_statement_reset()
            raise
        return True

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
