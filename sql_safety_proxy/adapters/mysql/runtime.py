"""MySQL proxy listener runtime."""

from __future__ import annotations

import asyncio
from functools import partial

from sql_safety_proxy.proxy import ProxyOptions

from .connection import handle_mysql_connection


async def _tracked_mysql_connection(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    *,
    opts: ProxyOptions,
    connection_tasks: set[asyncio.Task[None]],
) -> None:
    task = asyncio.current_task()
    if task is not None:
        connection_tasks.add(task)
    try:
        await handle_mysql_connection(
            client_reader,
            client_writer,
            opts,
        )
    finally:
        if task is not None:
            connection_tasks.discard(task)


async def start_mysql_proxy(
    opts: ProxyOptions,
) -> None:
    """Start the MySQL safety-proxy listener."""

    connection_tasks: set[asyncio.Task[None]] = set()
    client_handler = partial(
        _tracked_mysql_connection,
        opts=opts,
        connection_tasks=connection_tasks,
    )

    server = await asyncio.start_server(
        client_handler,
        host="0.0.0.0",
        port=opts.listen_port,
    )

    addresses = ", ".join(
        str(sock.getsockname())
        for sock in (server.sockets or [])
    )

    print(
        "[proxy] MySQL/MariaDB safety proxy listening on "
        f"{addresses or f'0.0.0.0:{opts.listen_port}'} "
        "and forwarding to the configured backend"
    )

    try:
        async with server:
            await server.serve_forever()
    finally:
        active = list(connection_tasks)
        for task in active:
            task.cancel()
        if active:
            await asyncio.gather(*active, return_exceptions=True)
