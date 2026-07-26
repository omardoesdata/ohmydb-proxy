"""The intercepting proxy - wires together protocol framing, classification,
risk estimation, and confirmation, using asyncio streams.

Handles BOTH protocols Postgres clients use:
 - Simple Query ('Q') - what psql's `-c` and most ad hoc tools send.
 - Extended Query (Parse/Bind/Execute) - what most real drivers and ORMs
   (asyncpg, psycopg2, JDBC, ...) send, even for a single one-off query.
Missing the extended protocol would mean the proxy only protects ad hoc
terminal sessions and silently lets application traffic through unchecked -
so both paths funnel into the same classify -> estimate -> confirm flow.
"""
import asyncio
from dataclasses import dataclass, field

from .pg_protocol import (
    is_negotiation_request,
    FrontendFramer,
    FrontendMessage,
    parse_simple_query_text,
    parse_startup_params,
    build_error_response,
    build_ready_for_query,
)
from .extended_protocol import parse_parse_message, parse_bind_message, parse_execute_message, BindMessage
from .sql_classifier import classify, Classification, Dialect
from .risk_estimator import estimate_affected_rows, DbConnectionOptions
from .confirmation import ConfirmationProvider, QueryContext
from .param_decoder import decode_param
from .preview_builder import substitute_params


@dataclass
class ProxyOptions:
    listen_port: int
    target_host: str
    target_port: int
    dialect: Dialect
    # Credentials the PROXY ITSELF uses to run read-only preview queries.
    # Deliberately separate from whatever auth the connecting client uses -
    # Postgres's SCRAM auth never puts a plaintext password on the wire for
    # us to capture and reuse.
    estimator_user: str
    estimator_password: str
    confirmation_provider: ConfirmationProvider


@dataclass
class ConnectionState:
    database: str = "postgres"
    # statement_name -> raw SQL text (with $1, $2... placeholders), from Parse messages.
    prepared_statements: dict = field(default_factory=dict)
    # portal_name -> BindMessage, from Bind messages.
    portals: dict = field(default_factory=dict)


async def _pipe_raw(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        writer.close()


async def _estimate(classification: Classification, opts: ProxyOptions, database: str):
    """Runs classification.preview_query on a side connection. Returns (rows, error)."""
    if not classification.preview_query:
        return None, None
    try:
        db_opts = DbConnectionOptions(
            host=opts.target_host, port=opts.target_port,
            user=opts.estimator_user, password=opts.estimator_password,
            database=database,
        )
        rows = await estimate_affected_rows(classification.preview_query, db_opts)
        return rows, None
    except Exception as e:
        return None, str(e)


async def _confirm_and_decide(
    sql: str,
    classification: Classification,
    estimated_rows,
    estimate_error,
    approx_note: str,
    opts: ProxyOptions,
) -> bool:
    print(
        f'[proxy] RISKY: "{sql}" -> {classification.reason}'
        + (f" (estimated {estimated_rows} rows{approx_note})" if estimated_rows is not None else "")
    )
    ctx = QueryContext(sql=sql, classification=classification,
                        estimated_rows=estimated_rows, estimate_error=estimate_error)
    approved = await opts.confirmation_provider.confirm(ctx)
    print(f"[proxy] decision: {'APPROVED, forwarding' if approved else 'BLOCKED'}")
    return approved


def _blocked_error(classification: Classification, estimated_rows) -> bytes:
    reason = (
        f"Query blocked by sql-safety-proxy: would affect {estimated_rows} row(s). {classification.reason}"
        if estimated_rows is not None
        else f"Query blocked by sql-safety-proxy: {classification.reason}"
    )
    return build_error_response(reason)


async def _handle_simple_query(
    msg: FrontendMessage, backend_writer: asyncio.StreamWriter,
    client_writer: asyncio.StreamWriter, opts: ProxyOptions, state: ConnectionState,
) -> None:
    sql = parse_simple_query_text(msg.payload)
    classification = classify(sql, opts.dialect)

    if classification.risk != "risky":
        backend_writer.write(msg.raw)
        await backend_writer.drain()
        return

    estimated_rows, estimate_error = await _estimate(classification, opts, state.database)
    approved = await _confirm_and_decide(sql, classification, estimated_rows, estimate_error, "", opts)

    if approved:
        backend_writer.write(msg.raw)
        await backend_writer.drain()
    else:
        client_writer.write(_blocked_error(classification, estimated_rows))
        client_writer.write(build_ready_for_query("I"))
        await client_writer.drain()


async def _handle_execute(
    msg: FrontendMessage, backend_writer: asyncio.StreamWriter,
    client_writer: asyncio.StreamWriter, opts: ProxyOptions, state: ConnectionState,
) -> None:
    execute = parse_execute_message(msg.payload)
    bind = state.portals.get(execute.portal_name)

    if bind is None:
        # Unknown portal (e.g. a protocol sequence we don't recognize) - fail
        # safe by forwarding rather than risking a hang, but log it since
        # this represents a real gap worth tightening later.
        print(f"[proxy] warning: Execute for unknown portal {execute.portal_name!r}, forwarding without a check")
        backend_writer.write(msg.raw)
        await backend_writer.drain()
        return

    sql_template = state.prepared_statements.get(bind.statement_name, "")
    classification = classify(sql_template, opts.dialect)

    if classification.risk != "risky":
        backend_writer.write(msg.raw)
        await backend_writer.drain()
        return

    estimated_rows = None
    estimate_error = None
    approx_note = ""
    if classification.preview_query:
        decoded = [decode_param(v, fc) for v, fc in zip(bind.param_values, bind.format_codes)]
        literal_query, any_heuristic = substitute_params(classification.preview_query, decoded)
        if literal_query is None:
            estimate_error = "could not decode one or more bound parameters - showing query without a row estimate"
        else:
            if any_heuristic:
                approx_note = ", approximate - decoded from binary protocol"
            estimated_rows, estimate_error = await _estimate(
                Classification(risk="risky", statement_type=classification.statement_type,
                                reason=classification.reason, preview_query=literal_query),
                opts, state.database,
            )

    approved = await _confirm_and_decide(sql_template, classification, estimated_rows, estimate_error, approx_note, opts)

    if approved:
        backend_writer.write(msg.raw)
        await backend_writer.drain()
    else:
        client_writer.write(_blocked_error(classification, estimated_rows))
        # No ReadyForQuery here: the client will send its own Sync next, which we
        # forward normally - the backend answers that Sync with ReadyForQuery itself,
        # since we never actually put it in a mid-command state.
        await client_writer.drain()


async def _handle_frontend_message(
    msg: FrontendMessage, backend_writer: asyncio.StreamWriter,
    client_writer: asyncio.StreamWriter, opts: ProxyOptions, state: ConnectionState,
) -> None:
    if msg.type == "Q":
        await _handle_simple_query(msg, backend_writer, client_writer, opts, state)
        return

    if msg.type == "P":  # Parse - just record the statement text, harmless to forward immediately
        parsed = parse_parse_message(msg.payload)
        state.prepared_statements[parsed.statement_name] = parsed.query
        backend_writer.write(msg.raw)
        await backend_writer.drain()
        return

    if msg.type == "B":  # Bind - just record the portal's bound values, harmless to forward immediately
        bind = parse_bind_message(msg.payload)
        state.portals[bind.portal_name] = bind
        backend_writer.write(msg.raw)
        await backend_writer.drain()
        return

    if msg.type == "E":  # Execute - this is where a query actually runs, so this is what we intercept
        await _handle_execute(msg, backend_writer, client_writer, opts, state)
        return

    # Everything else (Describe, Flush, Sync, Close, Terminate, password/SASL
    # messages, ...) carries no execution risk on its own - pass through.
    backend_writer.write(msg.raw)
    await backend_writer.drain()


async def _handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, opts: ProxyOptions) -> None:
    backend_reader = None
    backend_writer = None
    framer = FrontendFramer()
    state = ConnectionState()
    past_startup = False

    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break

            if not past_startup:
                if is_negotiation_request(chunk):
                    # We don't proxy TLS - tell the client "no SSL" and wait for the real StartupMessage.
                    writer.write(b"N")
                    await writer.drain()
                    continue

                params = parse_startup_params(chunk)
                state.database = params.get("database") or params.get("user") or "postgres"
                backend_reader, backend_writer = await asyncio.open_connection(opts.target_host, opts.target_port)
                backend_writer.write(chunk)  # forward the StartupMessage unchanged
                await backend_writer.drain()
                past_startup = True
                asyncio.create_task(_pipe_raw(backend_reader, writer))  # backend responses pass straight through
                continue

            messages = framer.push(chunk)
            for msg in messages:
                await _handle_frontend_message(msg, backend_writer, writer, opts, state)
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        writer.close()
        if backend_writer:
            backend_writer.close()


async def start_intercepting_proxy(opts: ProxyOptions) -> None:
    server = await asyncio.start_server(
        lambda r, w: _handle_client(r, w, opts), "127.0.0.1", opts.listen_port
    )
    print(f"[proxy] listening on 127.0.0.1:{opts.listen_port}, protecting {opts.target_host}:{opts.target_port}")
    async with server:
        await server.serve_forever()
