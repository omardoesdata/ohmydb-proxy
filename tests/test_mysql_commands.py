from __future__ import annotations

import pytest

from sql_safety_proxy.adapters.mysql.protocol import (
    COM_INIT_DB,
    COM_QUERY,
    COM_QUIT,
    COM_STMT_CLOSE,
    COM_STMT_EXECUTE,
    COM_STMT_PREPARE,
    COM_STMT_RESET,
    COM_STMT_SEND_LONG_DATA,
    MySqlCommandKind,
    MySqlLogicalMessage,
    MySqlProtocolError,
    classify_command,
    parse_logical_command,
)


def logical_message(payload: bytes) -> MySqlLogicalMessage:
    return MySqlLogicalMessage(
        first_sequence_id=0,
        last_sequence_id=0,
        payload=payload,
        raw_packets=b"",
        packet_count=1,
    )


def test_classifies_query_command():
    command = classify_command(
        COM_QUERY,
        b"SELECT 1",
    )

    assert command.command_code == COM_QUERY
    assert command.kind == MySqlCommandKind.QUERY
    assert command.payload == b"SELECT 1"


def test_classifies_init_db_command():
    command = classify_command(
        COM_INIT_DB,
        b"sql_safety_v06",
    )

    assert command.kind == MySqlCommandKind.INIT_DB
    assert command.payload == b"sql_safety_v06"


def test_classifies_quit_command():
    command = classify_command(COM_QUIT, b"")

    assert command.kind == MySqlCommandKind.QUIT
    assert command.payload == b""


@pytest.mark.parametrize(
    "command_code",
    [
        COM_STMT_PREPARE,
        COM_STMT_EXECUTE,
        COM_STMT_SEND_LONG_DATA,
        COM_STMT_CLOSE,
        COM_STMT_RESET,
    ],
)
def test_prepared_statement_commands_are_explicitly_unsupported(
    command_code,
):
    command = classify_command(command_code, b"payload")

    assert command.kind == MySqlCommandKind.PREPARED_STATEMENT


def test_unknown_command_is_classified_as_unsupported():
    command = classify_command(0x0E, b"")

    assert command.command_code == 0x0E
    assert command.kind == MySqlCommandKind.UNSUPPORTED


def test_parse_logical_command_extracts_code_and_payload():
    command = parse_logical_command(
        logical_message(b"\x03SELECT 1")
    )

    assert command.command_code == COM_QUERY
    assert command.kind == MySqlCommandKind.QUERY
    assert command.payload == b"SELECT 1"


def test_parse_logical_command_rejects_empty_message():
    with pytest.raises(
        MySqlProtocolError,
        match="logical command message is empty",
    ):
        parse_logical_command(logical_message(b""))
