"""MySQL proxy listener runtime."""

from __future__ import annotations

import asyncio
from functools import partial

from sql_safety_proxy.proxy import ProxyOptions

from .connection import handle_mysql_connection


async def start_mysql_proxy(
    opts: ProxyOptions,
) -> None:
    """Start the MySQL safety-proxy listener."""

    client_handler = partial(
        handle_mysql_connection,
        opts=opts,
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
        f"and forwarding to "
        f"{opts.target_host}:{opts.target_port}"
    )

    async with server:
        await server.serve_forever()
