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
from contextlib import suppress
from dataclasses import dataclass, field, replace
from typing import Optional

from .audit import JsonlAuditLogger, build_audit_event
from .confirmation import ConfirmationProvider, QueryContext
from .extended_protocol import (
    BindMessage,
    parse_bind_message,
    parse_close_message,
    parse_execute_message,
    parse_parse_message,
)
from .fail_safe import (
    FailSafeMode,
    ProtocolGapAction,
    evaluate_protocol_gap,
)
from .param_decoder import decode_param
from .pg_protocol import (
    BackendFramer,
    DEFAULT_MAX_MESSAGE_BYTES,
    FrontendFramer,
    FrontendMessage,
    ProtocolMessageError,
    StartupFramer,
    build_error_response,
    build_ready_for_query,
    is_negotiation_request,
    parse_ready_for_query_status,
    parse_simple_query_text,
    parse_startup_params,
)
from .policy import (
    PolicyAction,
    PolicyConfig,
    PolicyDecision,
    Severity,
    evaluate_policy,
)
from .preview_builder import substitute_params
from .adapters.registry import get_adapter
from .risk_estimator import DbConnectionOptions
from .sql_classifier import (
    Classification,
    Dialect,
    classify,
)
from .sanitization import safe_exception_summary, sanitize_sql


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
    adapter_name: str = "postgres"
    database_name: str = "postgres"
    estimate_timeout_seconds: float = 8.0
    backend_connect_timeout_seconds: float = 10.0
    socket_read_timeout_seconds: float | None = 300.0
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES
    max_session_items: int = 256
    max_session_state_bytes: int = 8 * 1024 * 1024

    policy_config: PolicyConfig = field(
        default_factory=PolicyConfig
    )

    audit_logger: Optional[JsonlAuditLogger] = None
    fail_safe_mode: FailSafeMode = FailSafeMode.BALANCED


@dataclass
class ConnectionState:
    database: str = "postgres"
    transaction_status: str = "I"
    extended_error_pending: bool = False

    prepared_statements: dict[str, str] = field(default_factory=dict)
    portals: dict[str, BindMessage] = field(default_factory=dict)
    max_items: int = 256
    max_state_bytes: int = 8 * 1024 * 1024

    @staticmethod
    def _portal_bytes(name: str, bind: BindMessage) -> int:
        return (
            len(name.encode("utf-8"))
            + len(bind.statement_name.encode("utf-8"))
            + sum(
                len(value)
                for value in bind.param_values
                if value is not None
            )
        )

    def _state_bytes(self) -> int:
        return sum(
            len(name.encode("utf-8")) + len(query.encode("utf-8"))
            for name, query in self.prepared_statements.items()
        ) + sum(
            self._portal_bytes(name, bind)
            for name, bind in self.portals.items()
        )

    def register_statement(self, name: str, query: str) -> None:
        if (
            name not in self.prepared_statements
            and len(self.prepared_statements) >= self.max_items
        ):
            raise ProtocolMessageError(
                "PostgreSQL prepared-statement registry limit exceeded"
            )
        projected = self._state_bytes()
        previous = self.prepared_statements.get(name)
        if previous is not None:
            projected -= len(name.encode("utf-8")) + len(
                previous.encode("utf-8")
            )
        projected += len(name.encode("utf-8")) + len(query.encode("utf-8"))
        if projected > self.max_state_bytes:
            raise ProtocolMessageError(
                "PostgreSQL per-session state size limit exceeded"
            )
        if name == "":
            self.portals = {
                portal_name: bind
                for portal_name, bind in self.portals.items()
                if bind.statement_name != ""
            }
        self.prepared_statements[name] = query

    def register_portal(self, bind: BindMessage) -> None:
        if (
            bind.portal_name not in self.portals
            and len(self.portals) >= self.max_items
        ):
            raise ProtocolMessageError(
                "PostgreSQL portal registry limit exceeded"
            )
        projected = self._state_bytes()
        previous = self.portals.get(bind.portal_name)
        if previous is not None:
            projected -= self._portal_bytes(bind.portal_name, previous)
        projected += self._portal_bytes(bind.portal_name, bind)
        if projected > self.max_state_bytes:
            raise ProtocolMessageError(
                "PostgreSQL per-session state size limit exceeded"
            )
        self.portals[bind.portal_name] = bind

    def close_statement(self, name: str) -> None:
        self.prepared_statements.pop(name, None)
        self.portals = {
            portal_name: bind
            for portal_name, bind in self.portals.items()
            if bind.statement_name != name
        }

    def close_portal(self, name: str) -> None:
        self.portals.pop(name, None)

    def update_transaction_status(self, status: str) -> None:
        self.transaction_status = status
        if status == "I":
            self.portals.clear()


async def _pipe_backend(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    state: ConnectionState,
    *,
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
    read_timeout_seconds: float | None = None,
) -> None:
    """Forward backend responses while tracking transaction state."""

    framer = BackendFramer(max_message_bytes=max_message_bytes)
    try:
        while True:
            read = reader.read(65536)
            chunk = (
                await asyncio.wait_for(read, timeout=read_timeout_seconds)
                if read_timeout_seconds is not None
                else await read
            )
            if not chunk:
                break

            messages = framer.push(chunk)
            for message in messages:
                if message.type == "Z":
                    state.update_transaction_status(
                        parse_ready_for_query_status(message.payload)
                    )

            writer.write(chunk)
            await writer.drain()

    except (ConnectionResetError, BrokenPipeError, asyncio.TimeoutError):
        pass
    except ProtocolMessageError:
        print(
            "[proxy] PostgreSQL backend protocol error; "
            "connection closed fail-safe"
        )
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

        adapter = get_adapter(opts.adapter_name)
        rows = await adapter.estimate_rows(
            classification.preview_query,
            db_options,
        )

        return rows, None

    except Exception as exc:
        return None, safe_exception_summary(
            exc, "row-impact estimation"
        )


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
            f"{safe_exception_summary(exc, 'audit write')}"
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

    display_sql = sanitize_sql(sql)

    _print_policy_result(
        sql=display_sql,
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
            sql=display_sql,
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
        sql=display_sql,
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


async def _handle_protocol_gap(
    *,
    protocol: str,
    reason: str,
    sql: str,
    client_writer: asyncio.StreamWriter,
    backend_writer: asyncio.StreamWriter,
    raw_message: bytes,
    database: str,
    opts: ProxyOptions,
    state: ConnectionState | None = None,
    extended_recovery: bool = False,
) -> bool:
    """Handle SQL execution that cannot be reconstructed safely.

    Returns True when the original message was forwarded.
    """

    gap_decision = evaluate_protocol_gap(
        opts.fail_safe_mode,
        reason,
    )

    classification = Classification(
        risk="unknown",
        statement_type="PROTOCOL_GAP",
        reason=reason,
        impact_kind="protocol",
        severity=Severity.CRITICAL,
    )

    policy_decision = PolicyDecision(
        action=(
            PolicyAction.ALLOW
            if gap_decision.action == ProtocolGapAction.ALLOW
            else PolicyAction.BLOCK
        ),
        severity=classification.severity,
        reason=gap_decision.reason,
    )

    forwarded = gap_decision.action == ProtocolGapAction.ALLOW
    final_decision = (
        "ALLOWED_PROTOCOL_GAP"
        if forwarded
        else "BLOCKED_PROTOCOL_GAP"
    )

    _print_policy_result(
        sql=sql,
        classification=classification,
        decision=policy_decision,
        estimated_rows=None,
        approximate=False,
        protocol=protocol,
    )

    await _write_audit_event(
        sql=sql,
        protocol=protocol,
        classification=classification,
        decision=policy_decision,
        final_decision=final_decision,
        estimated_rows=None,
        estimate_error=reason,
        approximate=False,
        database=database,
        opts=opts,
    )

    if forwarded:
        backend_writer.write(raw_message)
        await backend_writer.drain()
        return True

    client_writer.write(
        build_error_response(
            "Query blocked by sql-safety-proxy. "
            f"Protocol gap: {gap_decision.reason}.",
            sql_state="0A000",
        )
    )
    if state is not None and extended_recovery:
        state.extended_error_pending = True
    elif state is not None:
        client_writer.write(build_ready_for_query(state.transaction_status))
    await client_writer.drain()
    return False


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
        build_ready_for_query(state.transaction_status)
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
        await _handle_protocol_gap(
            protocol="extended",
            reason=(
                "Execute referenced an unknown portal"
            ),
            sql="<unavailable>",
            client_writer=client_writer,
            backend_writer=backend_writer,
            raw_message=msg.raw,
            database=state.database,
            opts=opts,
            state=state,
            extended_recovery=True,
        )
        return

    sql_template = state.prepared_statements.get(
        bind.statement_name
    )

    if sql_template is None:
        await _handle_protocol_gap(
            protocol="extended",
            reason=(
                "Portal references an unknown prepared statement"
            ),
            sql="<unavailable>",
            client_writer=client_writer,
            backend_writer=backend_writer,
            raw_message=msg.raw,
            database=state.database,
            opts=opts,
            state=state,
            extended_recovery=True,
        )
        return

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
    state.extended_error_pending = True

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

    if state.extended_error_pending:
        if msg.type == "S":
            backend_writer.write(msg.raw)
            await backend_writer.drain()
            state.extended_error_pending = False
        elif msg.type == "X":
            backend_writer.write(msg.raw)
            await backend_writer.drain()
        # PostgreSQL ignores extended-protocol messages until Sync after error.
        return

    try:
        if msg.type == "Q":
            await _handle_simple_query(msg, backend_writer, client_writer, opts, state)
            return

        if msg.type == "P":
            parsed = parse_parse_message(msg.payload)
            state.register_statement(parsed.statement_name, parsed.query)
            backend_writer.write(msg.raw)
            await backend_writer.drain()
            return

        if msg.type == "B":
            bind = parse_bind_message(msg.payload)
            state.register_portal(bind)
            backend_writer.write(msg.raw)
            await backend_writer.drain()
            return

        if msg.type == "E":
            await _handle_execute(msg, backend_writer, client_writer, opts, state)
            return

        if msg.type == "C":
            close = parse_close_message(msg.payload)
            if close.target_type == "S":
                state.close_statement(close.name)
            else:
                state.close_portal(close.name)
            backend_writer.write(msg.raw)
            await backend_writer.drain()
            return

        backend_writer.write(msg.raw)
        await backend_writer.drain()

    except ProtocolMessageError as exc:
        await _handle_protocol_gap(
            protocol="simple" if msg.type == "Q" else "extended",
            reason=f"Malformed frontend message {msg.type!r}: {exc}",
            sql="<unavailable>",
            client_writer=client_writer,
            backend_writer=backend_writer,
            raw_message=msg.raw,
            database=state.database,
            opts=opts,
            state=state,
            extended_recovery=msg.type != "Q",
        )


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

    framer = FrontendFramer(max_message_bytes=opts.max_message_bytes)
    startup_framer = StartupFramer(
        max_message_bytes=opts.max_message_bytes
    )
    state = ConnectionState(
        max_items=opts.max_session_items,
        max_state_bytes=opts.max_session_state_bytes,
    )
    past_startup = False
    backend_task: asyncio.Task[None] | None = None

    try:
        while True:
            read = reader.read(65536)
            chunk = (
                await asyncio.wait_for(
                    read,
                    timeout=opts.socket_read_timeout_seconds,
                )
                if opts.socket_read_timeout_seconds is not None
                else await read
            )

            if not chunk:
                break

            if not past_startup:
                startup_message = startup_framer.push(chunk)
                if startup_message is None:
                    continue

                if is_negotiation_request(startup_message):
                    # The proxy currently does not terminate TLS.
                    writer.write(b"N")
                    await writer.drain()
                    startup_framer = StartupFramer(
                        max_message_bytes=opts.max_message_bytes
                    )
                    continue

                params = parse_startup_params(
                    startup_message
                )

                state.database = (
                    params.get("database")
                    or params.get("user")
                    or "postgres"
                )

                backend_reader, backend_writer = (
                    await asyncio.wait_for(
                        asyncio.open_connection(
                            opts.target_host,
                            opts.target_port,
                        ),
                        timeout=opts.backend_connect_timeout_seconds,
                    )
                )

                backend_writer.write(startup_message)
                await backend_writer.drain()

                past_startup = True

                backend_task = asyncio.create_task(
                    _pipe_backend(
                        backend_reader,
                        writer,
                        state,
                        max_message_bytes=opts.max_message_bytes,
                        read_timeout_seconds=(
                            opts.socket_read_timeout_seconds
                        ),
                    )
                )

                continue

            try:
                messages = framer.push(chunk)
            except ProtocolMessageError as exc:
                writer.write(
                    build_error_response(
                        f"Malformed PostgreSQL frontend frame: {exc}",
                        sql_state="08P01",
                    )
                )
                await writer.drain()
                break

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
        asyncio.TimeoutError,
    ):
        pass

    except Exception as exc:
        print(
            "[proxy] client connection error: "
            f"{safe_exception_summary(exc, 'PostgreSQL client session')}"
        )

    finally:
        if backend_task is not None and not backend_task.done():
            backend_task.cancel()
        if backend_task is not None:
            await asyncio.gather(
                backend_task,
                return_exceptions=True,
            )

        writer.close()
        with suppress(
            ConnectionResetError,
            BrokenPipeError,
            asyncio.CancelledError,
        ):
            await writer.wait_closed()

        if backend_writer:
            backend_writer.close()
            with suppress(
                ConnectionResetError,
                BrokenPipeError,
                asyncio.CancelledError,
            ):
                await backend_writer.wait_closed()


async def start_postgres_proxy(
    opts: ProxyOptions,
) -> None:
    """Start the PostgreSQL protocol runtime."""

    connection_tasks: set[asyncio.Task[None]] = set()

    async def tracked_client(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            connection_tasks.add(task)
        try:
            await _handle_client(reader, writer, opts)
        finally:
            if task is not None:
                connection_tasks.discard(task)

    server = await asyncio.start_server(
        tracked_client,
        "127.0.0.1",
        opts.listen_port,
    )

    print(
        f"[proxy] listening on 127.0.0.1:{opts.listen_port}, "
        "protecting the configured PostgreSQL backend"
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
        f"{opts.policy_config.estimation_failure_action.value}, "
        f"multi_statement="
        f"{opts.policy_config.multi_statement_action.value}"
    )

    print(
        "[proxy] fail-safe mode: "
        f"{opts.fail_safe_mode.value}"
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
            f"[proxy] audit logging: {status}"
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



async def start_intercepting_proxy(
    opts: ProxyOptions,
) -> None:
    """Resolve and start the configured database adapter."""

    adapter = get_adapter(opts.adapter_name)
    adapter.validate_runtime(opts)

    if opts.dialect != adapter.dialect:
        raise ValueError(
            f"Configured SQL dialect {opts.dialect!r} "
            f"does not match adapter {adapter.name!r} "
            f"dialect {adapter.dialect!r}"
        )

    print(
        f"[proxy] adapter: {adapter.name} "
        f"({adapter.display_name}), capabilities="
        f"{adapter.capabilities.as_dict()}"
    )

    await adapter.start_proxy(opts)
