"""Per-connection socket lifecycle for the MySQL proxy."""

from __future__ import annotations

import asyncio
from contextlib import suppress

from sql_safety_proxy.proxy import ProxyOptions

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

    if writer.is_closing():
        return

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
        chunk = await reader.read(READ_CHUNK_BYTES)

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
) -> None:
    """Read backend bytes and pass them through the relay."""

    while True:
        chunk = await reader.read(READ_CHUNK_BYTES)

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
            await asyncio.open_connection(
                opts.target_host,
                opts.target_port,
            )
        )

        state = MySqlRelayState(
            database=opts.database_name,
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
    ) as exc:
        print(
            "[proxy] MySQL connection closed after protocol or "
            f"network error: {exc}"
        )

    except OSError as exc:
        print(
            "[proxy] failed to connect to MySQL backend "
            f"{opts.target_host}:{opts.target_port}: {exc}"
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
