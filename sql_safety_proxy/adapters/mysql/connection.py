"""Per-connection socket lifecycle for the MySQL proxy."""

from __future__ import annotations

import asyncio
from contextlib import suppress

from sql_safety_proxy.proxy import ProxyOptions
from sql_safety_proxy.sanitization import safe_exception_summary

from .protocol import MySqlProtocolError
from .relay import (
    MySqlRelayState,
    process_backend_chunk,
    process_client_chunk,
)


READ_CHUNK_BYTES = 64 * 1024


async def close_stream_writer(
    writer: asyncio.StreamWriter | None,
) -> None:
    """Close a stream writer and wait for shutdown when supported."""

    if writer is None:
        return

    if not writer.is_closing():
        writer.close()

    with suppress(
        ConnectionResetError,
        BrokenPipeError,
        asyncio.CancelledError,
    ):
        await writer.wait_closed()


async def pump_mysql_client(
    *,
    reader: asyncio.StreamReader,
    backend_writer: asyncio.StreamWriter,
    client_writer: asyncio.StreamWriter,
    state: MySqlRelayState,
    opts: ProxyOptions,
) -> None:
    """Read client bytes and pass them through the inspected relay."""

    while True:
        read = reader.read(READ_CHUNK_BYTES)
        chunk = (
            await asyncio.wait_for(
                read,
                timeout=opts.socket_read_timeout_seconds,
            )
            if opts.socket_read_timeout_seconds is not None
            else await read
        )

        if not chunk:
            return

        await process_client_chunk(
            chunk=chunk,
            state=state,
            backend_writer=backend_writer,
            client_writer=client_writer,
            opts=opts,
        )

        if state.session.closing:
            return


async def pump_mysql_backend(
    *,
    reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    state: MySqlRelayState,
    read_timeout_seconds: float | None = None,
) -> None:
    """Read backend bytes and pass them through the relay."""

    while True:
        read = reader.read(READ_CHUNK_BYTES)
        chunk = (
            await asyncio.wait_for(read, timeout=read_timeout_seconds)
            if read_timeout_seconds is not None
            else await read
        )

        if not chunk:
            return

        await process_backend_chunk(
            chunk=chunk,
            state=state,
            client_writer=client_writer,
        )


async def handle_mysql_connection(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    opts: ProxyOptions,
) -> None:
    """Handle one client connection to the MySQL safety proxy."""

    backend_writer: asyncio.StreamWriter | None = None
    client_task: asyncio.Task[None] | None = None
    backend_task: asyncio.Task[None] | None = None

    try:
        backend_reader, backend_writer = (
            await asyncio.wait_for(
                asyncio.open_connection(
                    opts.target_host,
                    opts.target_port,
                ),
                timeout=opts.backend_connect_timeout_seconds,
            )
        )

        state = MySqlRelayState(
            database=opts.database_name,
            max_packet_bytes=opts.max_message_bytes,
            max_session_items=opts.max_session_items,
            max_session_state_bytes=opts.max_session_state_bytes,
        )

        client_task = asyncio.create_task(
            pump_mysql_client(
                reader=client_reader,
                backend_writer=backend_writer,
                client_writer=client_writer,
                state=state,
                opts=opts,
            ),
            name="mysql-client-to-backend",
        )

        backend_task = asyncio.create_task(
            pump_mysql_backend(
                reader=backend_reader,
                client_writer=client_writer,
                state=state,
                read_timeout_seconds=opts.socket_read_timeout_seconds,
            ),
            name="mysql-backend-to-client",
        )

        done, pending = await asyncio.wait(
            {client_task, backend_task},
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()

        if pending:
            await asyncio.gather(
                *pending,
                return_exceptions=True,
            )

        for task in done:
            task.result()

    except (
        ConnectionResetError,
        BrokenPipeError,
        MySqlProtocolError,
        asyncio.TimeoutError,
    ) as exc:
        print(
            "[proxy] MySQL connection closed after protocol or "
            "network error: "
            f"{safe_exception_summary(exc, 'MySQL client session')}"
        )

    except OSError as exc:
        print(
            "[proxy] MySQL backend connection failed "
            f"({type(exc).__name__})"
        )

    finally:
        for task in (client_task, backend_task):
            if task is not None and not task.done():
                task.cancel()

        remaining = [
            task
            for task in (client_task, backend_task)
            if task is not None
        ]
        if remaining:
            await asyncio.gather(
                *remaining,
                return_exceptions=True,
            )

        await close_stream_writer(backend_writer)
        await close_stream_writer(client_writer)
