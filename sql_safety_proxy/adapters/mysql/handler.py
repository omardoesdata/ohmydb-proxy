"""Policy handling for authenticated MySQL commands."""

from __future__ import annotations

import asyncio
from dataclasses import replace

from sql_safety_proxy.fail_safe import (
    ProtocolGapAction,
    evaluate_protocol_gap,
)
from sql_safety_proxy.policy import (
    PolicyAction,
    PolicyDecision,
    Severity,
)
from sql_safety_proxy.proxy import (
    ProxyOptions,
    _estimate,
    _evaluate_and_decide,
    _print_policy_result,
    _write_audit_event,
)
from sql_safety_proxy.sql_classifier import (
    Classification,
    classify,
)

from .protocol import (
    COM_STMT_EXECUTE,
    MySqlLogicalMessage,
    MySqlProtocolError,
    build_error_packet,
    parse_query,
)


MYSQL_POLICY_ERROR_CODE = 1148
MYSQL_PROTOCOL_GAP_ERROR_CODE = 1235
MYSQL_SQL_STATE = "42000"
MYSQL_PROTOCOL_GAP_SQL_STATE = "0A000"


async def handle_mysql_query(
    *,
    message: MySqlLogicalMessage,
    command_payload: bytes,
    database: str,
    backend_writer: asyncio.StreamWriter,
    client_writer: asyncio.StreamWriter,
    opts: ProxyOptions,
) -> bool:
    """Inspect one COM_QUERY and forward it only when approved.

    Returns True when the original logical message was forwarded.
    """

    sql = parse_query(command_payload)
    classification = classify(sql, dialect=opts.dialect)

    estimated_rows, estimate_error = await _estimate(
        classification,
        opts,
        database,
    )

    approved, decision = await _evaluate_and_decide(
        sql=sql,
        protocol="mysql-com-query",
        classification=classification,
        estimated_rows=estimated_rows,
        estimate_error=estimate_error,
        approximate=False,
        database=database,
        opts=opts,
    )

    if approved:
        backend_writer.write(message.raw_packets)
        await backend_writer.drain()
        return True

    client_writer.write(
        build_mysql_policy_error(
            classification=classification,
            estimated_rows=estimated_rows,
            decision=decision,
            sequence_id=(message.last_sequence_id + 1) % 256,
        )
    )
    await client_writer.drain()
    return False


async def handle_mysql_stmt_execute(
    *,
    message: MySqlLogicalMessage,
    inspection_sql: str,
    sql_description: str,
    estimate_safe: bool,
    database: str,
    backend_writer: asyncio.StreamWriter,
    client_writer: asyncio.StreamWriter,
    opts: ProxyOptions,
) -> bool:
    """Inspect and apply policy to a reconstructed COM_STMT_EXECUTE."""

    inspection_classification = classify(
        inspection_sql,
        dialect=opts.dialect,
    )
    if inspection_classification.statement_type in {
        "EMPTY",
        "UNPARSEABLE",
    }:
        return await handle_mysql_protocol_gap(
            reason=(
                "Reconstructed COM_STMT_EXECUTE SQL could not be "
                "parsed safely"
            ),
            command_code=COM_STMT_EXECUTE,
            raw_message=message.raw_packets,
            response_sequence_id=(message.last_sequence_id + 1) % 256,
            database=database,
            backend_writer=backend_writer,
            client_writer=client_writer,
            opts=opts,
        )

    if estimate_safe:
        estimated_rows, estimate_error = await _estimate(
            inspection_classification,
            opts,
            database,
        )
    else:
        estimated_rows = None
        estimate_error = (
            "Prepared-statement parameter semantics cannot be "
            "estimated safely"
        )

    if estimate_error is not None:
        estimate_error = (
            "Prepared-statement row-impact estimation failed"
        )

    classification = replace(
        inspection_classification,
        preview_query=None,
    )

    approved, decision = await _evaluate_and_decide(
        # Prepared SQL and parameter values can contain secrets. Keep both
        # out of console, confirmation, and audit output while inspecting
        # the reconstructed statement internally.
        sql=sql_description,
        protocol="mysql-com-stmt-execute",
        classification=classification,
        estimated_rows=estimated_rows,
        estimate_error=estimate_error,
        approximate=False,
        database=database,
        opts=opts,
    )

    if approved:
        backend_writer.write(message.raw_packets)
        await backend_writer.drain()
        return True

    client_writer.write(
        build_mysql_policy_error(
            classification=classification,
            estimated_rows=estimated_rows,
            decision=decision,
            sequence_id=(message.last_sequence_id + 1) % 256,
        )
    )
    await client_writer.drain()
    return False


async def handle_mysql_protocol_gap(
    *,
    reason: str,
    command_code: int | None,
    raw_message: bytes,
    response_sequence_id: int,
    database: str,
    backend_writer: asyncio.StreamWriter,
    client_writer: asyncio.StreamWriter,
    opts: ProxyOptions,
) -> bool:
    """Apply fail-safe policy to uninspectable MySQL traffic."""

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
        severity=Severity.CRITICAL,
        reason=gap_decision.reason,
    )

    forwarded = (
        gap_decision.action == ProtocolGapAction.ALLOW
    )

    sql_description = (
        f"MYSQL_COMMAND_0x{command_code:02X}"
        if command_code is not None
        else "MYSQL_MALFORMED_COMMAND"
    )

    _print_policy_result(
        sql=sql_description,
        classification=classification,
        decision=policy_decision,
        estimated_rows=None,
        approximate=False,
        protocol="mysql-protocol-gap",
    )

    await _write_audit_event(
        sql=sql_description,
        protocol="mysql-protocol-gap",
        classification=classification,
        decision=policy_decision,
        final_decision=(
            "ALLOWED_PROTOCOL_GAP"
            if forwarded
            else "BLOCKED_PROTOCOL_GAP"
        ),
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
        build_error_packet(
            (
                "Query blocked by sql-safety-proxy. "
                f"Protocol gap: {gap_decision.reason}."
            ),
            sequence_id=response_sequence_id,
            error_code=MYSQL_PROTOCOL_GAP_ERROR_CODE,
            sql_state=MYSQL_PROTOCOL_GAP_SQL_STATE,
        )
    )
    await client_writer.drain()
    return False


def build_mysql_policy_error(
    *,
    classification: Classification,
    estimated_rows: int | None,
    decision: PolicyDecision,
    sequence_id: int,
) -> bytes:
    """Build a MySQL ERR packet for a rejected SQL statement."""

    parts = [
        "Query blocked by sql-safety-proxy.",
        f"Policy: {decision.reason}.",
        f"Severity: {decision.severity.value}.",
        f"Operation: {classification.statement_type}.",
    ]

    if estimated_rows is not None:
        parts.append(
            f"Estimated rows affected: {estimated_rows}."
        )

    return build_error_packet(
        " ".join(parts),
        sequence_id=sequence_id,
        error_code=MYSQL_POLICY_ERROR_CODE,
        sql_state=MYSQL_SQL_STATE,
    )
