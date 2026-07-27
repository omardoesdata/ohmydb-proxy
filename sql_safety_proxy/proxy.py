"""PostgreSQL wire proxy with classification, estimation, policy control,
confirmation, and JSONL audit logging.

Supported PostgreSQL client execution paths:

- Simple Query protocol:
  Used by psql and some direct SQL clients.

- Extended Query protocol:
  Parse -> Bind -> Execute, used by asyncpg, psycopg, JDBC, ORMs, and most
  application drivers.

Both execution paths pass through the same safety workflow:

    classify -> estimate -> policy -> confirm/block/allow -> audit
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from typing import Optional

from .audit import JsonlAuditLogger, build_audit_event
from .confirmation import ConfirmationProvider, QueryContext
from .extended_protocol import (
    BindMessage,
    parse_bind_message,
    parse_execute_message,
    parse_parse_message,
)
from .param_decoder import decode_param
from .pg_protocol import (
    FrontendFramer,
    FrontendMessage,
    build_error_response,
    build_ready_for_query,
    is_negotiation_request,
    parse_simple_query_text,
    parse_startup_params,
)
from .policy import (
    PolicyAction,
    PolicyConfig,
    PolicyDecision,
    evaluate_policy,
)
from .preview_builder import substitute_params
from .risk_estimator import (
    DbConnectionOptions,
    estimate_affected_rows,
)
from .sql_classifier import (
    Classification,
    Dialect,
    classify,
)


@dataclass
class ProxyOptions:
    listen_port: int
    target_host: str
    target_port: int
    dialect: Dialect

    estimator_user: str
    estimator_password: str
    confirmation_provider: ConfirmationProvider

    database_engine: str = "postgres"
    estimate_timeout_seconds: float = 8.0

    policy_config: PolicyConfig = field(
        default_factory=PolicyConfig
    )

    audit_logger: Optional[JsonlAuditLogger] = None


@dataclass
class ConnectionState:
    database: str = "postgres"

    # Prepared statement name -> SQL template.
    prepared_statements: dict[str, str] = field(
        default_factory=dict
    )

    # Portal name -> parsed Bind message.
    portals: dict[str, BindMessage] = field(
        default_factory=dict
    )


async def _pipe_raw(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    """Forward backend PostgreSQL responses to the connected client."""

    try:
        while True:
            chunk = await reader.read(65536)

            if not chunk:
                break

            writer.write(chunk)
            await writer.drain()

    except (
        ConnectionResetError,
        BrokenPipeError,
    ):
        pass

    finally:
        writer.close()


async def _estimate(
    classification: Classification,
    opts: ProxyOptions,
    database: str,
) -> tuple[Optional[int], Optional[str]]:
    """Execute a generated read-only preview query.

    Returns:

        (estimated_rows, error_message)
    """

    if not classification.preview_query:
        return None, None

    try:
        db_options = DbConnectionOptions(
            host=opts.target_host,
            port=opts.target_port,
            user=opts.estimator_user,
            password=opts.estimator_password,
            database=database,
            timeout_seconds=opts.estimate_timeout_seconds,
        )

        rows = await estimate_affected_rows(
            classification.preview_query,
            db_options,
            engine=opts.database_engine,
        )

        return rows, None

    except Exception as exc:
        return None, str(exc)


def _print_policy_result(
    sql: str,
    classification: Classification,
    decision: PolicyDecision,
    estimated_rows: Optional[int],
    approximate: bool,
    protocol: str,
) -> None:
    """Print one structured safety decision to the proxy console."""

    estimate_text = "unavailable"

    if estimated_rows is not None:
        estimate_text = str(estimated_rows)

        if approximate:
            estimate_text += " approximate"

    print(
        f'[proxy] {decision.action.value}: "{sql}" '
        f"protocol={protocol} "
        f"operation={classification.statement_type} "
        f"table={classification.target_table or 'unknown'} "
        f"severity={decision.severity.value} "
        f"estimated_rows={estimate_text} "
        f"reason={decision.reason}"
    )


async def _write_audit_event(
    *,
    sql: str,
    protocol: str,
    classification: Classification,
    decision: PolicyDecision,
    final_decision: str,
    estimated_rows: Optional[int],
    estimate_error: Optional[str],
    approximate: bool,
    database: str,
    opts: ProxyOptions,
) -> None:
    """Append the final safety decision to the configured audit log."""

    if opts.audit_logger is None:
        return

    event = build_audit_event(
        sql=sql,
        database=database,
        operation=classification.statement_type,
        target_table=classification.target_table,
        severity=decision.severity.value,
        policy_action=decision.action.value,
        final_decision=final_decision,
        estimated_rows=estimated_rows,
        estimate_error=estimate_error,
        classification_reason=classification.reason,
        policy_reason=decision.reason,
        approximate_estimate=approximate,
        protocol=protocol,
    )

    try:
        await opts.audit_logger.log(event)
    except Exception as exc:
        # Audit failure must be visible, but it must not crash the proxy
        # after a safety decision has already been made.
        print(
            "[proxy] warning: failed to write audit event: "
            f"{exc}"
        )


async def _evaluate_and_decide(
    sql: str,
    protocol: str,
    classification: Classification,
    estimated_rows: Optional[int],
    estimate_error: Optional[str],
    approximate: bool,
    database: str,
    opts: ProxyOptions,
) -> tuple[bool, PolicyDecision]:
    """Apply policy and return whether the SQL should be forwarded."""

    decision = evaluate_policy(
        classification=classification,
        estimated_rows=estimated_rows,
        estimate_error=estimate_error,
        config=opts.policy_config,
    )

    _print_policy_result(
        sql=sql,
        classification=classification,
        decision=decision,
        estimated_rows=estimated_rows,
        approximate=approximate,
        protocol=protocol,
    )

    if decision.action == PolicyAction.ALLOW:
        approved = True
        final_decision = "ALLOWED"

    elif decision.action == PolicyAction.BLOCK:
        approved = False
        final_decision = "BLOCKED_BY_POLICY"

    else:
        context = QueryContext(
            sql=sql,
            classification=classification,
            estimated_rows=estimated_rows,
            estimate_error=estimate_error,
            policy_decision=decision,
            database=database,
            approximate_estimate=approximate,
        )

        approved = await opts.confirmation_provider.confirm(
            context
        )

        final_decision = (
            "APPROVED_BY_USER"
            if approved
            else "BLOCKED_BY_USER"
        )

        print(
            "[proxy] user decision: "
            + (
                "APPROVED"
                if approved
                else "BLOCKED"
            )
        )

    await _write_audit_event(
        sql=sql,
        protocol=protocol,
        classification=classification,
        decision=decision,
        final_decision=final_decision,
        estimated_rows=estimated_rows,
        estimate_error=estimate_error,
        approximate=approximate,
        database=database,
        opts=opts,
    )

    return approved, decision


def _blocked_error(
    classification: Classification,
    estimated_rows: Optional[int],
    decision: PolicyDecision,
) -> bytes:
    """Build a PostgreSQL error response for rejected queries."""

    parts = [
        "Query blocked by sql-safety-proxy.",
        f"Policy: {decision.reason}.",
        f"Severity: {decision.severity.value}.",
        f"Operation: {classification.statement_type}.",
    ]

    if classification.target_table:
        parts.append(
            f"Table: {classification.target_table}."
        )

    if estimated_rows is not None:
        parts.append(
            f"Estimated rows affected: {estimated_rows}."
        )

    return build_error_response(
        " ".join(parts)
    )


async def _handle_simple_query(
    msg: FrontendMessage,
    backend_writer: asyncio.StreamWriter,
    client_writer: asyncio.StreamWriter,
    opts: ProxyOptions,
    state: ConnectionState,
) -> None:
    """Handle PostgreSQL Simple Query messages."""

    sql = parse_simple_query_text(
        msg.payload
    )

    classification = classify(
        sql,
        opts.dialect,
    )

    if classification.risk == "safe":
        backend_writer.write(msg.raw)
        await backend_writer.drain()
        return

    estimated_rows, estimate_error = await _estimate(
        classification,
        opts,
        state.database,
    )

    approved, decision = await _evaluate_and_decide(
        sql=sql,
        protocol="simple",
        classification=classification,
        estimated_rows=estimated_rows,
        estimate_error=estimate_error,
        approximate=False,
        database=state.database,
        opts=opts,
    )

    if approved:
        backend_writer.write(msg.raw)
        await backend_writer.drain()
        return

    client_writer.write(
        _blocked_error(
            classification,
            estimated_rows,
            decision,
        )
    )

    client_writer.write(
        build_ready_for_query("I")
    )

    await client_writer.drain()


async def _handle_execute(
    msg: FrontendMessage,
    backend_writer: asyncio.StreamWriter,
    client_writer: asyncio.StreamWriter,
    opts: ProxyOptions,
    state: ConnectionState,
) -> None:
    """Handle PostgreSQL Extended Query Execute messages."""

    execute = parse_execute_message(
        msg.payload
    )

    bind: Optional[BindMessage] = state.portals.get(
        execute.portal_name
    )

    if bind is None:
        print(
            "[proxy] warning: Execute received for unknown portal "
            f"{execute.portal_name!r}; forwarding because no SQL "
            "statement is available to classify"
        )

        backend_writer.write(msg.raw)
        await backend_writer.drain()
        return

    sql_template = state.prepared_statements.get(
        bind.statement_name,
        "",
    )

    classification = classify(
        sql_template,
        opts.dialect,
    )

    if classification.risk == "safe":
        backend_writer.write(msg.raw)
        await backend_writer.drain()
        return

    estimated_rows: Optional[int] = None
    estimate_error: Optional[str] = None
    approximate = False

    if classification.preview_query:
        decoded_parameters = [
            decode_param(
                value,
                format_code,
            )
            for value, format_code in zip(
                bind.param_values,
                bind.format_codes,
            )
        ]

        literal_query, used_heuristic = substitute_params(
            classification.preview_query,
            decoded_parameters,
        )

        if literal_query is None:
            estimate_error = (
                "Could not decode one or more bound parameters"
            )

        else:
            approximate = used_heuristic

            preview_classification = replace(
                classification,
                preview_query=literal_query,
            )

            estimated_rows, estimate_error = await _estimate(
                preview_classification,
                opts,
                state.database,
            )

    approved, decision = await _evaluate_and_decide(
        sql=sql_template,
        protocol="extended",
        classification=classification,
        estimated_rows=estimated_rows,
        estimate_error=estimate_error,
        approximate=approximate,
        database=state.database,
        opts=opts,
    )

    if approved:
        backend_writer.write(msg.raw)
        await backend_writer.drain()
        return

    client_writer.write(
        _blocked_error(
            classification,
            estimated_rows,
            decision,
        )
    )

    # The client will normally send Sync after Execute. The backend then
    # returns ReadyForQuery, so we do not fabricate one in this path.
    await client_writer.drain()


async def _handle_frontend_message(
    msg: FrontendMessage,
    backend_writer: asyncio.StreamWriter,
    client_writer: asyncio.StreamWriter,
    opts: ProxyOptions,
    state: ConnectionState,
) -> None:
    """Route one framed PostgreSQL frontend message."""

    if msg.type == "Q":
        await _handle_simple_query(
            msg,
            backend_writer,
            client_writer,
            opts,
            state,
        )
        return

    if msg.type == "P":
        parsed = parse_parse_message(
            msg.payload
        )

        state.prepared_statements[
            parsed.statement_name
        ] = parsed.query

        backend_writer.write(msg.raw)
        await backend_writer.drain()
        return

    if msg.type == "B":
        bind = parse_bind_message(
            msg.payload
        )

        state.portals[
            bind.portal_name
        ] = bind

        backend_writer.write(msg.raw)
        await backend_writer.drain()
        return

    if msg.type == "E":
        await _handle_execute(
            msg,
            backend_writer,
            client_writer,
            opts,
            state,
        )
        return

    # Describe, Flush, Sync, Close, Terminate and authentication messages
    # do not directly execute SQL and are forwarded unchanged.
    backend_writer.write(msg.raw)
    await backend_writer.drain()


async def _handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    opts: ProxyOptions,
) -> None:
    """Handle one connected PostgreSQL client."""

    backend_reader: Optional[
        asyncio.StreamReader
    ] = None

    backend_writer: Optional[
        asyncio.StreamWriter
    ] = None

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
                    # The proxy currently does not terminate TLS.
                    writer.write(b"N")
                    await writer.drain()
                    continue

                params = parse_startup_params(
                    chunk
                )

                state.database = (
                    params.get("database")
                    or params.get("user")
                    or "postgres"
                )

                backend_reader, backend_writer = (
                    await asyncio.open_connection(
                        opts.target_host,
                        opts.target_port,
                    )
                )

                backend_writer.write(chunk)
                await backend_writer.drain()

                past_startup = True

                asyncio.create_task(
                    _pipe_raw(
                        backend_reader,
                        writer,
                    )
                )

                continue

            messages = framer.push(chunk)

            for message in messages:
                if backend_writer is None:
                    raise RuntimeError(
                        "Backend connection is unavailable"
                    )

                await _handle_frontend_message(
                    message,
                    backend_writer,
                    writer,
                    opts,
                    state,
                )

    except (
        ConnectionResetError,
        BrokenPipeError,
    ):
        pass

    except Exception as exc:
        print(
            "[proxy] client connection error: "
            f"{exc}"
        )

    finally:
        writer.close()

        if backend_writer:
            backend_writer.close()


async def start_intercepting_proxy(
    opts: ProxyOptions,
) -> None:
    """Start the PostgreSQL safety proxy."""

    server = await asyncio.start_server(
        lambda reader, writer: _handle_client(
            reader,
            writer,
            opts,
        ),
        "127.0.0.1",
        opts.listen_port,
    )

    print(
        f"[proxy] listening on 127.0.0.1:{opts.listen_port}, "
        f"protecting {opts.target_host}:{opts.target_port}"
    )

    print(
        "[proxy] policy: "
        f"auto_allow_max_rows="
        f"{opts.policy_config.auto_allow_max_rows}, "
        f"block_at_rows="
        f"{opts.policy_config.block_at_rows}, "
        f"no_where="
        f"{opts.policy_config.no_where_action.value}, "
        f"structural="
        f"{opts.policy_config.structural_action.value}, "
        f"unknown="
        f"{opts.policy_config.unknown_action.value}, "
        f"estimation_failure="
        f"{opts.policy_config.estimation_failure_action.value}"
    )

    if opts.audit_logger is None:
        print(
            "[proxy] audit logging: disabled"
        )
    else:
        status = (
            "enabled"
            if opts.audit_logger.enabled
            else "disabled"
        )

        print(
            f"[proxy] audit logging: {status}, "
            f"path={opts.audit_logger.path}"
        )

    async with server:
        await server.serve_forever()
