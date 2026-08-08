from __future__ import annotations

import asyncio

import pytest

from sql_safety_proxy.adapters.mysql.protocol import (
    CLIENT_DEPRECATE_EOF,
    CLIENT_PROTOCOL_41,
    MARIADB_CLIENT_CACHE_METADATA,
    MYSQL_TYPE_LONG,
    SERVER_MORE_RESULTS_EXISTS,
    SERVER_STATUS_AUTOCOMMIT,
    SERVER_STATUS_IN_TRANS,
    MySqlParameterType,
    MySqlProtocolError,
)
from sql_safety_proxy.adapters.mysql.session import (
    MySqlPreparedStatement,
    MySqlSessionState,
)


def test_begin_prepare_records_pending_sql():
    state = MySqlSessionState(database="app_db")

    state.begin_statement_prepare(
        "UPDATE safety_users SET active = ? WHERE id = ?"
    )

    assert (
        state.pending_statement_sql
        == "UPDATE safety_users SET active = ? WHERE id = ?"
    )


@pytest.mark.asyncio
async def test_pipelined_prepare_waits_for_complete_metadata():
    state = MySqlSessionState(database="app_db")
    state.begin_statement_prepare("SELECT ?")
    event = state.pending_prepare_event
    assert event is not None
    waiter = asyncio.create_task(
        state.wait_for_statement_prepare(event)
    )

    state.accept_statement_prepare_ok(
        statement_id=9,
        parameter_count=1,
        column_count=1,
        deprecate_eof=False,
    )
    await asyncio.sleep(0)
    assert not waiter.done()

    for payload in (
        b"parameter-definition",
        b"\xfe",
        b"column-definition",
        b"\xfe",
    ):
        finished = state.consume_statement_prepare_metadata(
            payload,
            capability_flags=0,
        )
    assert finished is True
    assert not waiter.done()

    state.finish_statement_prepare_response()
    assert await waiter is state.prepared_statements[9]
    assert state.last_prepared_statement_id == 9


@pytest.mark.asyncio
async def test_failed_prepare_wakes_pipeline_and_invalidates_last_id():
    state = MySqlSessionState(database="app_db")
    state.begin_statement_prepare("SELECT 1")
    state.complete_statement_prepare(
        statement_id=7,
        parameter_count=0,
        column_count=1,
    )
    state.begin_statement_prepare("invalid SQL")
    event = state.pending_prepare_event
    assert event is not None
    waiter = asyncio.create_task(
        state.wait_for_statement_prepare(event)
    )

    state.fail_statement_prepare()

    assert await waiter is None
    assert state.last_prepared_statement_id is None
    assert 7 in state.prepared_statements


def test_prepare_metadata_eof_is_validated():
    state = MySqlSessionState(database="app_db")
    state.begin_statement_prepare("SELECT ?")
    state.accept_statement_prepare_ok(
        statement_id=2,
        parameter_count=1,
        column_count=0,
        deprecate_eof=False,
    )
    state.consume_statement_prepare_metadata(
        b"parameter-definition",
        capability_flags=0,
    )

    with pytest.raises(MySqlProtocolError, match="metadata EOF"):
        state.consume_statement_prepare_metadata(
            b"not-an-eof",
            capability_flags=0,
        )


def test_transaction_state_tracks_ok_and_preserves_state_on_error():
    state = MySqlSessionState(database="app_db")
    state.begin_command_response("query")
    state.accept_command_response_packet(
        b"\x00\x00\x00\x03\x00\x00\x00",
        capability_flags=CLIENT_PROTOCOL_41,
    )
    assert state.transaction_active is True
    assert state.autocommit is True
    assert state.pending_command_response is None

    state.begin_command_response("query")
    state.accept_command_response_packet(
        b"\xff\x00\x00error",
        capability_flags=CLIENT_PROTOCOL_41,
    )
    assert state.transaction_active is True
    assert state.autocommit is True


def test_transaction_state_tracks_legacy_resultset_eof():
    state = MySqlSessionState(database="app_db")
    state.begin_command_response("query")

    for payload in (
        b"\x01",
        b"column-definition",
        b"\xfe\x00\x00\x03\x00",
        b"\x01x",
        b"\xfe\x00\x00\x02\x00",
    ):
        state.accept_command_response_packet(
            payload,
            capability_flags=CLIENT_PROTOCOL_41,
        )

    assert state.transaction_active is False
    assert state.autocommit is True
    assert state.pending_command_response is None


def test_binary_row_does_not_complete_deprecated_eof_response():
    state = MySqlSessionState(database="app_db")
    flags = CLIENT_PROTOCOL_41 | CLIENT_DEPRECATE_EOF
    state.begin_command_response("stmt_execute")
    state.accept_command_response_packet(b"\x01", capability_flags=flags)
    state.accept_command_response_packet(
        b"column-definition", capability_flags=flags
    )
    state.accept_command_response_packet(
        b"\x00\x00\x2a\x00\x00\x00", capability_flags=flags
    )

    assert state.pending_command_response == "stmt_execute"

    state.accept_command_response_packet(
        b"\xfe\x00\x00\x02\x00\x00\x00",
        capability_flags=flags,
    )
    assert state.pending_command_response is None
    assert state.autocommit is True


def test_mariadb_cached_result_metadata_can_be_omitted():
    state = MySqlSessionState(database="app_db")
    flags = CLIENT_PROTOCOL_41 | MARIADB_CLIENT_CACHE_METADATA
    state.begin_command_response("stmt_execute")
    state.accept_command_response_packet(
        b"\x01\x00", capability_flags=flags
    )
    assert state.command_response_stage == "metadata_eof"
    state.accept_command_response_packet(
        b"\xfe\x00\x00\x01\x00", capability_flags=flags
    )
    state.accept_command_response_packet(
        b"\x00\x04", capability_flags=flags
    )
    assert state.pending_command_response == "stmt_execute"
    state.accept_command_response_packet(
        b"\xfe\x00\x00\x02\x00", capability_flags=flags
    )
    assert state.pending_command_response is None


def test_more_results_keeps_response_pending_until_final_ok():
    state = MySqlSessionState(database="app_db")
    state.begin_command_response("query")
    state.accept_command_response_packet(
        b"\x00\x00\x00"
        + (SERVER_STATUS_AUTOCOMMIT | SERVER_MORE_RESULTS_EXISTS).to_bytes(
            2, "little"
        )
        + b"\x00\x00",
        capability_flags=CLIENT_PROTOCOL_41,
    )
    assert state.pending_command_response == "query"

    state.accept_command_response_packet(
        b"\x00\x00\x00"
        + SERVER_STATUS_IN_TRANS.to_bytes(2, "little")
        + b"\x00\x00",
        capability_flags=CLIENT_PROTOCOL_41,
    )
    assert state.pending_command_response is None
    assert state.transaction_active is True
    assert state.autocommit is False


def test_transaction_state_is_isolated_between_sessions():
    first = MySqlSessionState(database="first")
    second = MySqlSessionState(database="second")
    first.update_transaction_status(SERVER_STATUS_IN_TRANS)
    second.update_transaction_status(SERVER_STATUS_AUTOCOMMIT)

    assert first.transaction_active is True
    assert first.autocommit is False
    assert second.transaction_active is False
    assert second.autocommit is True


def test_begin_prepare_rejects_empty_sql():
    state = MySqlSessionState(database="app_db")

    with pytest.raises(
        MySqlProtocolError,
        match="cannot be empty",
    ):
        state.begin_statement_prepare("   ")


def test_begin_prepare_rejects_second_pending_prepare():
    state = MySqlSessionState(database="app_db")
    state.begin_statement_prepare("SELECT ?")

    with pytest.raises(
        MySqlProtocolError,
        match="already pending",
    ):
        state.begin_statement_prepare("SELECT 2")


def test_complete_prepare_registers_statement():
    state = MySqlSessionState(database="app_db")
    state.begin_statement_prepare(
        "UPDATE safety_users SET active = ? WHERE id = ?"
    )

    statement = state.complete_statement_prepare(
        statement_id=42,
        parameter_count=2,
        column_count=0,
    )

    assert statement == MySqlPreparedStatement(
        statement_id=42,
        sql="UPDATE safety_users SET active = ? WHERE id = ?",
        parameter_count=2,
        column_count=0,
    )
    assert state.prepared_statements[42] == statement
    assert state.pending_statement_sql is None


def test_complete_prepare_requires_pending_sql():
    state = MySqlSessionState(database="app_db")

    with pytest.raises(
        MySqlProtocolError,
        match="No MySQL statement prepare is pending",
    ):
        state.complete_statement_prepare(
            statement_id=1,
            parameter_count=0,
            column_count=0,
        )


def test_prepare_error_discards_pending_sql():
    state = MySqlSessionState(database="app_db")
    state.begin_statement_prepare("SELECT ?")

    state.fail_statement_prepare()

    assert state.pending_statement_sql is None
    assert state.prepared_statements == {}


def test_get_prepared_statement_requires_known_id():
    state = MySqlSessionState(database="app_db")

    with pytest.raises(
        MySqlProtocolError,
        match="Unknown MySQL prepared statement id 99",
    ):
        state.get_prepared_statement(99)


def test_close_prepared_statement_removes_it():
    state = MySqlSessionState(database="app_db")
    state.begin_statement_prepare("SELECT ?")
    state.complete_statement_prepare(
        statement_id=7,
        parameter_count=1,
        column_count=1,
    )

    removed = state.close_prepared_statement(7)

    assert removed.statement_id == 7
    assert state.prepared_statements == {}


def test_close_unknown_prepared_statement_is_idempotent():
    state = MySqlSessionState(database="app_db")

    assert state.close_prepared_statement(77) is None


def test_parameter_metadata_and_long_data_follow_statement_lifecycle():
    state = MySqlSessionState(database="app_db")
    state.begin_statement_prepare("SELECT ?")
    statement = state.complete_statement_prepare(
        statement_id=7,
        parameter_count=1,
        column_count=1,
    )
    parameter_types = (MySqlParameterType(MYSQL_TYPE_LONG),)

    state.register_statement_parameter_types(7, parameter_types)
    state.mark_statement_long_data(7, 0)

    assert statement.parameter_types == parameter_types
    assert statement.long_data_parameters == {0}

    state.reset_prepared_statement(7)

    assert statement.parameter_types is None
    assert statement.long_data_parameters == set()


def test_long_data_rejects_unknown_or_out_of_range_parameters():
    state = MySqlSessionState(database="app_db")
    state.begin_statement_prepare("SELECT ?")
    state.complete_statement_prepare(
        statement_id=7,
        parameter_count=1,
        column_count=1,
    )

    with pytest.raises(MySqlProtocolError, match="out-of-range"):
        state.mark_statement_long_data(7, 1)

    with pytest.raises(MySqlProtocolError, match="Unknown"):
        state.mark_statement_long_data(8, 0)


def test_ping_lifecycle_accepts_only_ok_or_error():
    state = MySqlSessionState(database="app_db")

    state.begin_ping()
    assert state.pending_ping is True
    assert state.complete_ping(b"\x00") is True
    assert state.pending_ping is False

    state.begin_ping()
    assert state.complete_ping(b"\xfferror") is False
    assert state.pending_ping is False

    state.begin_ping()
    with pytest.raises(MySqlProtocolError, match="Unexpected"):
        state.complete_ping(b"\x01")
    assert state.pending_ping is False


def test_reset_ok_clears_only_target_metadata_and_keeps_registry():
    state = MySqlSessionState(database="app_db")
    for statement_id in (7, 8):
        state.begin_statement_prepare("SELECT ?")
        state.complete_statement_prepare(
            statement_id=statement_id,
            parameter_count=1,
            column_count=1,
        )
        state.register_statement_parameter_types(
            statement_id,
            (MySqlParameterType(MYSQL_TYPE_LONG),),
        )

    state.begin_statement_reset(7)
    assert state.pending_statement_reset_id == 7
    assert state.complete_statement_reset(b"\x00") is True

    assert set(state.prepared_statements) == {7, 8}
    assert state.prepared_statements[7].parameter_types is None
    assert state.prepared_statements[8].parameter_types is not None
    assert state.pending_statement_reset_id is None


def test_reset_error_or_unexpected_packet_preserves_registry_metadata():
    state = MySqlSessionState(database="app_db")
    state.begin_statement_prepare("SELECT ?")
    statement = state.complete_statement_prepare(
        statement_id=7,
        parameter_count=1,
        column_count=1,
    )
    parameter_types = (MySqlParameterType(MYSQL_TYPE_LONG),)
    state.register_statement_parameter_types(7, parameter_types)

    state.begin_statement_reset(7)
    assert state.complete_statement_reset(b"\xfferror") is False
    assert statement.parameter_types == parameter_types

    state.begin_statement_reset(7)
    with pytest.raises(MySqlProtocolError, match="Unexpected"):
        state.complete_statement_reset(b"\x01")
    assert statement.parameter_types == parameter_types
    assert state.prepared_statements[7] is statement
    assert state.pending_statement_reset_id is None


def test_reset_requires_known_id_and_rejects_overlapping_acknowledgments():
    state = MySqlSessionState(database="app_db")
    state.begin_statement_prepare("SELECT ?")
    state.complete_statement_prepare(
        statement_id=7,
        parameter_count=1,
        column_count=1,
    )

    with pytest.raises(MySqlProtocolError, match="Unknown"):
        state.begin_statement_reset(8)

    state.begin_statement_reset(7)
    with pytest.raises(MySqlProtocolError, match="already pending"):
        state.begin_statement_reset(7)
    with pytest.raises(MySqlProtocolError, match="already pending"):
        state.begin_ping()
