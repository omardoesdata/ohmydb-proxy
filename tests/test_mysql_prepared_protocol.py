from __future__ import annotations

import pytest

from sql_safety_proxy.adapters.mysql.protocol import (
    COM_STMT_CLOSE,
    COM_STMT_EXECUTE,
    COM_STMT_PREPARE,
    COM_STMT_RESET,
    COM_STMT_SEND_LONG_DATA,
    MySqlCommandKind,
    MySqlProtocolError,
    classify_command,
    parse_stmt_execute,
    parse_stmt_prepare,
    parse_stmt_prepare_ok,
    parse_statement_id,
)


@pytest.mark.parametrize(
    ("command_code", "expected_kind"),
    [
        (
            COM_STMT_PREPARE,
            MySqlCommandKind.STMT_PREPARE,
        ),
        (
            COM_STMT_EXECUTE,
            MySqlCommandKind.STMT_EXECUTE,
        ),
        (
            COM_STMT_SEND_LONG_DATA,
            MySqlCommandKind.STMT_SEND_LONG_DATA,
        ),
        (
            COM_STMT_CLOSE,
            MySqlCommandKind.STMT_CLOSE,
        ),
        (
            COM_STMT_RESET,
            MySqlCommandKind.STMT_RESET,
        ),
    ],
)
def test_prepared_commands_have_distinct_kinds(
    command_code,
    expected_kind,
):
    command = classify_command(command_code, b"payload")

    assert command.kind == expected_kind


def test_parse_stmt_prepare_returns_sql():
    assert (
        parse_stmt_prepare(
            b"UPDATE safety_users SET active = ? WHERE id = ?"
        )
        == "UPDATE safety_users SET active = ? WHERE id = ?"
    )


def test_parse_stmt_prepare_rejects_empty_sql():
    with pytest.raises(
        MySqlProtocolError,
        match="contains no SQL text",
    ):
        parse_stmt_prepare(b"")


def test_parse_stmt_prepare_rejects_invalid_utf8():
    with pytest.raises(
        MySqlProtocolError,
        match="invalid UTF-8",
    ):
        parse_stmt_prepare(b"\xff")


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x01",
        b"\x01\x02",
        b"\x01\x02\x03",
    ],
)
def test_parse_statement_id_rejects_short_payload(payload):
    with pytest.raises(
        MySqlProtocolError,
        match="statement id",
    ):
        parse_statement_id(payload)


def test_parse_statement_id_reads_little_endian_value():
    assert (
        parse_statement_id(
            b"\x78\x56\x34\x12remaining"
        )
        == 0x12345678
    )


def test_parse_stmt_execute_reads_fixed_header():
    execution = parse_stmt_execute(
        b"\x78\x56\x34\x12"
        b"\x00"
        b"\x01\x00\x00\x00"
        b"parameter-data"
    )

    assert execution.statement_id == 0x12345678
    assert execution.flags == 0
    assert execution.iteration_count == 1
    assert execution.parameter_payload == b"parameter-data"


def test_parse_stmt_execute_rejects_short_header():
    with pytest.raises(
        MySqlProtocolError,
        match="shorter than 9 bytes",
    ):
        parse_stmt_execute(b"\x01\x00\x00\x00")


def test_parse_stmt_prepare_ok():
    result = parse_stmt_prepare_ok(
        b"\x00"
        b"\x78\x56\x34\x12"
        b"\x02\x00"
        b"\x03\x00"
        b"\x00"
        b"\x05\x00"
    )

    assert result.statement_id == 0x12345678
    assert result.column_count == 2
    assert result.parameter_count == 3
    assert result.warning_count == 5


def test_parse_stmt_prepare_ok_rejects_error_packet():
    with pytest.raises(
        MySqlProtocolError,
        match="not COM_STMT_PREPARE_OK",
    ):
        parse_stmt_prepare_ok(
            b"\xff\x15\x04#42000prepare failed"
        )


def test_parse_stmt_prepare_ok_rejects_short_packet():
    with pytest.raises(
        MySqlProtocolError,
        match="shorter than 12 bytes",
    ):
        parse_stmt_prepare_ok(b"\x00\x01")
