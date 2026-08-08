from __future__ import annotations

import struct

import pytest

from sql_safety_proxy.adapters.mysql.protocol import (
    CLIENT_PROTOCOL_41,
    MARIADB_CLIENT_CACHE_METADATA,
    COM_STMT_CLOSE,
    COM_STMT_EXECUTE,
    COM_STMT_PREPARE,
    COM_STMT_RESET,
    COM_STMT_SEND_LONG_DATA,
    MYSQL_TYPE_BLOB,
    MYSQL_TYPE_DATE,
    MYSQL_TYPE_DOUBLE,
    MYSQL_TYPE_FLOAT,
    MYSQL_TYPE_INT24,
    MYSQL_TYPE_LONG,
    MYSQL_TYPE_LONGLONG,
    MYSQL_TYPE_NEWDECIMAL,
    MYSQL_TYPE_SHORT,
    MYSQL_TYPE_TINY,
    MYSQL_TYPE_VAR_STRING,
    MYSQL_TYPE_YEAR,
    MYSQL_UNSIGNED_FLAG,
    MySqlCommandKind,
    MySqlParameterType,
    MySqlProtocolError,
    classify_command,
    parse_stmt_execute,
    parse_stmt_execute_parameters,
    parse_stmt_reset,
    parse_stmt_long_data,
    parse_stmt_prepare,
    parse_stmt_prepare_ok,
    parse_eof_packet_status,
    parse_ok_packet_status,
    parse_resultset_column_count,
    parse_resultset_header,
    parse_statement_id,
    reconstruct_stmt_execute_sql,
)


def test_parse_ok_packet_status_reads_transaction_flags():
    payload = b"\x00\x00\x00\x03\x00\x00\x00"

    assert parse_ok_packet_status(
        payload,
        capability_flags=CLIENT_PROTOCOL_41,
    ) == 3


def test_parse_ok_packet_status_rejects_truncation():
    with pytest.raises(MySqlProtocolError, match="missing"):
        parse_ok_packet_status(
            b"\x00\x00",
            capability_flags=CLIENT_PROTOCOL_41,
        )


def test_parse_eof_packet_status_reads_transaction_flags():
    assert parse_eof_packet_status(
        b"\xfe\x00\x00\x01\x20",
        capability_flags=CLIENT_PROTOCOL_41,
    ) == 0x2001


def test_parse_eof_packet_status_rejects_row_shaped_packet():
    with pytest.raises(MySqlProtocolError, match="not an EOF"):
        parse_eof_packet_status(
            b"\xfe" + b"x" * 8,
            capability_flags=CLIENT_PROTOCOL_41,
        )


def test_parse_resultset_column_count_is_strict():
    assert parse_resultset_column_count(b"\xfc\x2c\x01") == 300
    with pytest.raises(MySqlProtocolError, match="must be positive"):
        parse_resultset_column_count(b"\x00")


def test_parse_mariadb_resultset_metadata_indicator():
    assert parse_resultset_header(
        b"\x01\x00",
        capability_flags=MARIADB_CLIENT_CACHE_METADATA,
    ) == (1, False)
    assert parse_resultset_header(
        b"\x01\x01",
        capability_flags=MARIADB_CLIENT_CACHE_METADATA,
    ) == (1, True)
    with pytest.raises(MySqlProtocolError, match="must be 0 or 1"):
        parse_resultset_header(
            b"\x01\x02",
            capability_flags=MARIADB_CLIENT_CACHE_METADATA,
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


def test_parse_stmt_reset_requires_exact_statement_id():
    assert parse_stmt_reset(b"\x2a\x00\x00\x00") == 42

    for payload in (b"\x2a\x00\x00", b"\x2a\x00\x00\x00\x00"):
        with pytest.raises(MySqlProtocolError, match="exactly"):
            parse_stmt_reset(payload)


def test_parse_stmt_execute_rejects_short_header():
    with pytest.raises(
        MySqlProtocolError,
        match="shorter than 9 bytes",
    ):
        parse_stmt_execute(b"\x01\x00\x00\x00")


def execute_with_parameters(payload: bytes):
    return parse_stmt_execute(
        b"\x2a\x00\x00\x00"
        b"\x00"
        b"\x01\x00\x00\x00"
        + payload
    )


def test_parse_stmt_execute_decodes_scalar_parameter_types():
    payload = (
        b"\x00\x01"
        + bytes(
            [
                MYSQL_TYPE_LONG,
                0,
                MYSQL_TYPE_LONGLONG,
                MYSQL_UNSIGNED_FLAG,
                MYSQL_TYPE_FLOAT,
                0,
                MYSQL_TYPE_DOUBLE,
                0,
                MYSQL_TYPE_VAR_STRING,
                0,
            ]
        )
        + (-123).to_bytes(4, "little", signed=True)
        + (2**64 - 1).to_bytes(8, "little")
        + struct.pack("<f", 1.5)
        + struct.pack("<d", -2.25)
        + b"\x03a\x00b"
    )

    decoded = parse_stmt_execute_parameters(
        execute_with_parameters(payload),
        parameter_count=5,
    )

    assert [parameter.value for parameter in decoded.parameters] == [
        -123,
        2**64 - 1,
        1.5,
        -2.25,
        b"a\x00b",
    ]
    assert decoded.parameters[-1].sql_literal == "X'610062'"


@pytest.mark.parametrize(
    ("type_code", "size", "value", "unsigned"),
    [
        (MYSQL_TYPE_TINY, 1, -128, False),
        (MYSQL_TYPE_SHORT, 2, -32768, False),
        (MYSQL_TYPE_LONG, 4, -(2**31), False),
        (MYSQL_TYPE_INT24, 4, -(2**31), False),
        (MYSQL_TYPE_LONGLONG, 8, -(2**63), False),
        (MYSQL_TYPE_TINY, 1, 255, True),
        (MYSQL_TYPE_SHORT, 2, 65535, True),
        (MYSQL_TYPE_LONG, 4, 2**32 - 1, True),
        (MYSQL_TYPE_LONGLONG, 8, 2**64 - 1, True),
        (MYSQL_TYPE_YEAR, 2, 2026, True),
    ],
)
def test_parse_stmt_execute_decodes_integer_widths(
    type_code,
    size,
    value,
    unsigned,
):
    flags = MYSQL_UNSIGNED_FLAG if unsigned else 0
    decoded = parse_stmt_execute_parameters(
        execute_with_parameters(
            b"\x00\x01"
            + bytes([type_code, flags])
            + value.to_bytes(size, "little", signed=not unsigned)
        ),
        parameter_count=1,
    )

    assert decoded.parameters[0].value == value


def test_parse_stmt_execute_reuses_parameter_type_metadata():
    decoded = parse_stmt_execute_parameters(
        execute_with_parameters(
            b"\x00\x00" + (7).to_bytes(2, "little", signed=True)
        ),
        parameter_count=1,
        previous_types=(MySqlParameterType(MYSQL_TYPE_SHORT),),
    )

    assert decoded.new_params_bound is False
    assert decoded.parameters[0].value == 7


def test_parse_stmt_execute_decodes_null_bitmap_without_value_bytes():
    decoded = parse_stmt_execute_parameters(
        execute_with_parameters(
            b"\x02\x01"
            + bytes(
                [
                    MYSQL_TYPE_LONG,
                    0,
                    MYSQL_TYPE_VAR_STRING,
                    0,
                ]
            )
            + (9).to_bytes(4, "little", signed=True)
        ),
        parameter_count=2,
    )

    assert decoded.parameters[0].value == 9
    assert decoded.parameters[1].value is None
    assert decoded.parameters[1].sql_literal == "NULL"


def test_parse_stmt_execute_null_bitmap_crosses_byte_boundary():
    types = bytes([MYSQL_TYPE_LONG, 0]) * 9
    values = b"".join(
        value.to_bytes(4, "little", signed=True)
        for value in range(8)
    )

    decoded = parse_stmt_execute_parameters(
        execute_with_parameters(
            b"\x00\x01\x01" + types + values
        ),
        parameter_count=9,
    )

    assert [parameter.value for parameter in decoded.parameters[:8]] == (
        list(range(8))
    )
    assert decoded.parameters[8].value is None


def test_parse_stmt_execute_decodes_multibyte_length_encoded_binary():
    value = bytes(range(256)) + b"tail" * 11
    payload = (
        b"\x00\x01"
        + bytes([MYSQL_TYPE_VAR_STRING, 0])
        + b"\xfc"
        + len(value).to_bytes(2, "little")
        + value
    )

    decoded = parse_stmt_execute_parameters(
        execute_with_parameters(payload),
        parameter_count=1,
    )

    assert decoded.parameters[0].value == value


@pytest.mark.parametrize(
    ("type_code", "family"),
    [
        (MYSQL_TYPE_DATE, "temporal"),
        (MYSQL_TYPE_NEWDECIMAL, "decimal"),
        (MYSQL_TYPE_BLOB, "blob"),
        (0xF5, "unsupported"),
    ],
)
def test_parse_stmt_execute_rejects_uninspectable_types(
    type_code,
    family,
):
    with pytest.raises(MySqlProtocolError, match=family):
        parse_stmt_execute_parameters(
            execute_with_parameters(
                b"\x00\x01" + bytes([type_code, 0])
            ),
            parameter_count=1,
        )


def test_parse_stmt_execute_rejects_null_with_blob_metadata():
    with pytest.raises(MySqlProtocolError, match="blob"):
        parse_stmt_execute_parameters(
            execute_with_parameters(
                b"\x01\x01" + bytes([MYSQL_TYPE_BLOB, 0])
            ),
            parameter_count=1,
        )


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b"", "metadata is truncated"),
        (b"\x00\x02", "must be 0 or 1"),
        (b"\x00\x01\x03", "type metadata is truncated"),
        (
            b"\x00\x01" + bytes([MYSQL_TYPE_LONG, 0]) + b"\x01",
            "parameter 0 is truncated",
        ),
        (
            b"\x00\x01"
            + bytes([MYSQL_TYPE_VAR_STRING, 0])
            + b"\x02x",
            "parameter 0 is truncated",
        ),
    ],
)
def test_parse_stmt_execute_rejects_malformed_parameter_payload(
    payload,
    message,
):
    with pytest.raises(MySqlProtocolError, match=message):
        parse_stmt_execute_parameters(
            execute_with_parameters(payload),
            parameter_count=1,
        )


def test_parse_stmt_execute_rejects_metadata_reuse_before_registration():
    with pytest.raises(MySqlProtocolError, match="before metadata"):
        parse_stmt_execute_parameters(
            execute_with_parameters(b"\x00\x00"),
            parameter_count=1,
        )


def test_parse_stmt_execute_rejects_reused_metadata_count_mismatch():
    with pytest.raises(MySqlProtocolError, match="count does not match"):
        parse_stmt_execute_parameters(
            execute_with_parameters(b"\x00\x00"),
            parameter_count=1,
            previous_types=(),
        )


def test_parse_stmt_execute_without_parameters_rejects_trailing_data():
    with pytest.raises(MySqlProtocolError, match="trailing data"):
        parse_stmt_execute_parameters(
            execute_with_parameters(b"unexpected"),
            parameter_count=0,
        )


def test_parse_stmt_execute_rejects_huge_truncated_lenenc_value():
    with pytest.raises(MySqlProtocolError, match="parameter 0 is truncated"):
        parse_stmt_execute_parameters(
            execute_with_parameters(
                b"\x00\x01"
                + bytes([MYSQL_TYPE_VAR_STRING, 0])
                + b"\xfe"
                + (2**64 - 1).to_bytes(8, "little")
            ),
            parameter_count=1,
        )


def test_parse_stmt_execute_rejects_trailing_parameter_bytes():
    with pytest.raises(MySqlProtocolError, match="trailing data"):
        parse_stmt_execute_parameters(
            execute_with_parameters(
                b"\x00\x01"
                + bytes([MYSQL_TYPE_LONG, 0])
                + (1).to_bytes(4, "little", signed=True)
                + b"extra"
            ),
            parameter_count=1,
        )


def test_parse_stmt_execute_rejects_non_finite_float():
    with pytest.raises(MySqlProtocolError, match="not finite"):
        parse_stmt_execute_parameters(
            execute_with_parameters(
                b"\x00\x01"
                + bytes([MYSQL_TYPE_DOUBLE, 0])
                + struct.pack("<d", float("nan"))
            ),
            parameter_count=1,
        )


def test_reconstruct_stmt_execute_sql_skips_quotes_and_comments():
    decoded = parse_stmt_execute_parameters(
        execute_with_parameters(
            b"\x00\x01"
            + bytes([MYSQL_TYPE_LONG, 0])
            + (42).to_bytes(4, "little", signed=True)
        ),
        parameter_count=1,
    )

    sql = reconstruct_stmt_execute_sql(
        "UPDATE t SET note = '?' /* ? */ WHERE id = ? -- ?\n",
        decoded.parameters,
    )

    assert sql == (
        "UPDATE t SET note = '?' /* ? */ WHERE id = 42 -- ?\n"
    )


def test_reconstruct_stmt_execute_sql_rejects_placeholder_mismatch():
    with pytest.raises(MySqlProtocolError, match="more placeholders"):
        reconstruct_stmt_execute_sql("SELECT ?, ?", ())


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT /*!80000 ? */ ?",
        "SELECT /*M!100000 ? */ ?",
    ],
)
def test_reconstruct_stmt_execute_sql_rejects_executable_comments(sql):
    decoded = parse_stmt_execute_parameters(
        execute_with_parameters(
            b"\x00\x01"
            + bytes([MYSQL_TYPE_LONG, 0])
            + (1).to_bytes(4, "little", signed=True)
        ),
        parameter_count=1,
    )

    with pytest.raises(MySqlProtocolError, match="executable comment"):
        reconstruct_stmt_execute_sql(sql, decoded.parameters)


def test_reconstruct_stmt_execute_sql_rejects_ambiguous_backslash_escape():
    decoded = parse_stmt_execute_parameters(
        execute_with_parameters(
            b"\x00\x01"
            + bytes([MYSQL_TYPE_LONG, 0])
            + (1).to_bytes(4, "little", signed=True)
        ),
        parameter_count=1,
    )

    with pytest.raises(MySqlProtocolError, match="mode-dependent"):
        reconstruct_stmt_execute_sql(
            "SELECT 'ambiguous\\'text', ?",
            decoded.parameters,
        )


def test_reconstruct_stmt_execute_sql_skips_all_quoted_and_comment_forms():
    decoded = parse_stmt_execute_parameters(
        execute_with_parameters(
            b"\x00\x01"
            + bytes([MYSQL_TYPE_LONG, 0])
            + (5).to_bytes(4, "little", signed=True)
        ),
        parameter_count=1,
    )

    sql = reconstruct_stmt_execute_sql(
        'SELECT "?", `?`, \'it\'\'?\', ? # ?\n',
        decoded.parameters,
    )

    assert sql == 'SELECT "?", `?`, \'it\'\'?\', 5 # ?\n'


def test_parse_stmt_long_data_reads_identifiers_and_bytes():
    long_data = parse_stmt_long_data(
        b"\x2a\x00\x00\x00\x03\x00binary"
    )

    assert long_data.statement_id == 42
    assert long_data.parameter_id == 3
    assert long_data.data == b"binary"


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
