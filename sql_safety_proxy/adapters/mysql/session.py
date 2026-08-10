"""Authenticated MySQL session state."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from .protocol import (
    CLIENT_DEPRECATE_EOF,
    CLIENT_PROTOCOL_41,
    SERVER_MORE_RESULTS_EXISTS,
    SERVER_STATUS_AUTOCOMMIT,
    SERVER_STATUS_IN_TRANS,
    SERVER_STATUS_IN_TRANS_READONLY,
    MySqlParameterType,
    MySqlProtocolError,
    parse_eof_packet_status,
    parse_ok_packet_status,
    parse_resultset_header,
)


MYSQL_OK_PACKET = 0x00
MYSQL_ERR_PACKET = 0xFF


@dataclass
class MySqlPreparedStatement:
    statement_id: int
    sql: str
    parameter_count: int
    column_count: int
    parameter_types: tuple[MySqlParameterType, ...] | None = None
    long_data_parameters: set[int] = field(default_factory=set)


@dataclass
class MySqlSessionState:
    database: str
    max_prepared_statements: int = 256
    max_state_bytes: int = 8 * 1024 * 1024
    pending_database: str | None = None
    pending_statement_sql: str | None = None
    pending_prepare_event: asyncio.Event | None = None
    pending_prepared_statement_id: int | None = None
    pending_prepare_metadata_packets: int = 0
    pending_prepare_metadata_kinds: list[str] = field(
        default_factory=list
    )
    last_prepared_statement_id: int | None = None
    last_prepare_failed: bool = False
    pending_ping: bool = False
    pending_statement_reset_id: int | None = None
    pending_command_response: str | None = None
    command_response_stage: str = "initial"
    response_columns_remaining: int = 0
    prepared_statements: dict[int, MySqlPreparedStatement] = field(
        default_factory=dict
    )
    server_status_flags: int | None = None
    transaction_active: bool = False
    transaction_read_only: bool = False
    autocommit: bool = True
    closing: bool = False

    @property
    def has_pending_lifecycle_operation(self) -> bool:
        return any(
            (
                self.pending_database is not None,
                self.pending_statement_sql is not None,
                self.pending_ping,
                self.pending_statement_reset_id is not None,
                self.pending_command_response is not None,
            )
        )

    def _require_no_pending_lifecycle_operation(self) -> None:
        if self.has_pending_lifecycle_operation:
            raise MySqlProtocolError(
                "A MySQL command acknowledgment is already pending"
            )

    def _require_prepared_capacity(
        self,
        statement_id: int,
        sql: str,
    ) -> None:
        if (
            statement_id not in self.prepared_statements
            and len(self.prepared_statements)
            >= self.max_prepared_statements
        ):
            raise MySqlProtocolError(
                "MySQL prepared-statement registry limit exceeded"
            )

        current = sum(
            len(item.sql.encode("utf-8"))
            for item in self.prepared_statements.values()
        )
        previous = self.prepared_statements.get(statement_id)
        if previous is not None:
            current -= len(previous.sql.encode("utf-8"))
        if current + len(sql.encode("utf-8")) > self.max_state_bytes:
            raise MySqlProtocolError(
                "MySQL per-session state size limit exceeded"
            )

    def begin_database_change(self, database: str) -> None:
        normalized = database.strip()

        if not normalized:
            raise MySqlProtocolError(
                "COM_INIT_DB database name cannot be empty"
            )

        self._require_no_pending_lifecycle_operation()

        self.pending_database = normalized

    def complete_database_change(
        self,
        backend_payload: bytes,
    ) -> bool:
        """Apply a pending COM_INIT_DB only after backend OK.

        Returns True when the active database changed.
        """

        if self.pending_database is None:
            raise MySqlProtocolError(
                "No MySQL database change is pending"
            )

        if not backend_payload:
            self.pending_database = None
            raise MySqlProtocolError(
                "COM_INIT_DB backend response is empty"
            )

        marker = backend_payload[0]

        if marker == MYSQL_OK_PACKET:
            self.database = self.pending_database
            self.pending_database = None
            return True

        if marker == MYSQL_ERR_PACKET:
            self.pending_database = None
            return False

        self.pending_database = None
        raise MySqlProtocolError(
            "Unexpected backend response to COM_INIT_DB"
        )

    def begin_statement_prepare(self, sql: str) -> None:
        normalized = sql.strip()

        if not normalized:
            raise MySqlProtocolError(
                "COM_STMT_PREPARE SQL cannot be empty"
            )

        self._require_no_pending_lifecycle_operation()

        self.pending_statement_sql = normalized
        self.pending_prepare_event = asyncio.Event()
        self.pending_prepared_statement_id = None
        self.pending_prepare_metadata_packets = 0
        self.pending_prepare_metadata_kinds.clear()
        self.last_prepare_failed = False

    def complete_statement_prepare(
        self,
        *,
        statement_id: int,
        parameter_count: int,
        column_count: int,
    ) -> MySqlPreparedStatement:
        if self.pending_statement_sql is None:
            raise MySqlProtocolError(
                "No MySQL statement prepare is pending"
            )

        self._require_prepared_capacity(
            statement_id,
            self.pending_statement_sql,
        )
        statement = MySqlPreparedStatement(
            statement_id=statement_id,
            sql=self.pending_statement_sql,
            parameter_count=parameter_count,
            column_count=column_count,
        )

        self.prepared_statements[statement_id] = statement
        self.pending_statement_sql = None
        self.pending_prepared_statement_id = None
        self.pending_prepare_metadata_packets = 0
        self.pending_prepare_metadata_kinds.clear()
        self.last_prepared_statement_id = statement_id
        self.last_prepare_failed = False
        if self.pending_prepare_event is not None:
            self.pending_prepare_event.set()
        return statement

    def fail_statement_prepare(self) -> None:
        if self.pending_prepared_statement_id is not None:
            self.prepared_statements.pop(
                self.pending_prepared_statement_id,
                None,
            )
        self.pending_statement_sql = None
        self.pending_prepared_statement_id = None
        self.pending_prepare_metadata_packets = 0
        self.pending_prepare_metadata_kinds.clear()
        self.last_prepared_statement_id = None
        self.last_prepare_failed = True
        if self.pending_prepare_event is not None:
            self.pending_prepare_event.set()

    def accept_statement_prepare_ok(
        self,
        *,
        statement_id: int,
        parameter_count: int,
        column_count: int,
        deprecate_eof: bool,
    ) -> MySqlPreparedStatement:
        if self.pending_statement_sql is None:
            raise MySqlProtocolError(
                "No MySQL statement prepare is pending"
            )
        if self.pending_prepared_statement_id is not None:
            raise MySqlProtocolError(
                "Duplicate COM_STMT_PREPARE_OK packet"
            )

        self._require_prepared_capacity(
            statement_id,
            self.pending_statement_sql,
        )
        statement = MySqlPreparedStatement(
            statement_id=statement_id,
            sql=self.pending_statement_sql,
            parameter_count=parameter_count,
            column_count=column_count,
        )
        self.prepared_statements[statement_id] = statement
        self.pending_prepared_statement_id = statement_id
        kinds = ["parameter"] * parameter_count
        if parameter_count and not deprecate_eof:
            kinds.append("eof")
        kinds.extend(["column"] * column_count)
        if column_count and not deprecate_eof:
            kinds.append("eof")
        self.pending_prepare_metadata_kinds = kinds
        self.pending_prepare_metadata_packets = len(kinds)
        return statement

    def consume_statement_prepare_metadata(
        self,
        backend_payload: bytes,
        *,
        capability_flags: int,
    ) -> bool:
        if self.pending_prepared_statement_id is None:
            raise MySqlProtocolError(
                "No COM_STMT_PREPARE metadata is pending"
            )
        if self.pending_prepare_metadata_packets <= 0:
            raise MySqlProtocolError(
                "Unexpected extra COM_STMT_PREPARE metadata packet"
            )
        if not backend_payload:
            raise MySqlProtocolError(
                "COM_STMT_PREPARE metadata packet is empty"
            )
        kind = self.pending_prepare_metadata_kinds[0]
        if kind == "eof":
            if backend_payload[0] != 0xFE or len(backend_payload) >= 9:
                raise MySqlProtocolError(
                    "Expected COM_STMT_PREPARE metadata EOF packet"
                )
            if capability_flags & CLIENT_PROTOCOL_41:
                parse_eof_packet_status(
                    backend_payload,
                    capability_flags=capability_flags,
                )
        elif backend_payload[0] == MYSQL_ERR_PACKET:
            raise MySqlProtocolError(
                "COM_STMT_PREPARE metadata ended with an error"
            )
        self.pending_prepare_metadata_kinds.pop(0)
        self.pending_prepare_metadata_packets -= 1
        return self.pending_prepare_metadata_packets == 0

    def finish_statement_prepare_response(self) -> None:
        statement_id = self.pending_prepared_statement_id
        if statement_id is None:
            raise MySqlProtocolError(
                "No successful COM_STMT_PREPARE response is pending"
            )
        if self.pending_prepare_metadata_packets != 0:
            raise MySqlProtocolError(
                "COM_STMT_PREPARE metadata response is incomplete"
            )

        self.pending_statement_sql = None
        self.pending_prepared_statement_id = None
        self.pending_prepare_metadata_kinds.clear()
        self.last_prepared_statement_id = statement_id
        self.last_prepare_failed = False
        if self.pending_prepare_event is not None:
            self.pending_prepare_event.set()

    async def wait_for_statement_prepare(
        self,
        event: asyncio.Event,
    ) -> MySqlPreparedStatement | None:
        await event.wait()
        if self.last_prepare_failed:
            return None
        if self.last_prepared_statement_id is None:
            raise MySqlProtocolError(
                "COM_STMT_PREPARE completed without a statement id"
            )
        return self.get_prepared_statement(
            self.last_prepared_statement_id
        )

    def get_last_prepared_statement(self) -> MySqlPreparedStatement:
        if self.last_prepared_statement_id is None:
            raise MySqlProtocolError(
                "No reusable MariaDB prepared statement is available"
            )
        return self.get_prepared_statement(
            self.last_prepared_statement_id
        )

    def get_prepared_statement(
        self,
        statement_id: int,
    ) -> MySqlPreparedStatement:
        try:
            return self.prepared_statements[statement_id]
        except KeyError as exc:
            raise MySqlProtocolError(
                "Unknown MySQL prepared statement id "
                f"{statement_id}"
            ) from exc

    def close_prepared_statement(
        self,
        statement_id: int,
    ) -> MySqlPreparedStatement | None:
        statement = self.prepared_statements.pop(
            statement_id,
            None,
        )
        if self.last_prepared_statement_id == statement_id:
            self.last_prepared_statement_id = None
        return statement

    def register_statement_parameter_types(
        self,
        statement_id: int,
        parameter_types: tuple[MySqlParameterType, ...],
    ) -> None:
        statement = self.get_prepared_statement(statement_id)
        if len(parameter_types) != statement.parameter_count:
            raise MySqlProtocolError(
                "MySQL prepared-statement parameter type count mismatch"
            )
        statement.parameter_types = parameter_types
        statement.long_data_parameters.clear()

    def mark_statement_long_data(
        self,
        statement_id: int,
        parameter_id: int,
    ) -> None:
        statement = self.get_prepared_statement(statement_id)
        if parameter_id >= statement.parameter_count:
            raise MySqlProtocolError(
                "COM_STMT_SEND_LONG_DATA references out-of-range "
                f"parameter {parameter_id}"
            )
        statement.long_data_parameters.add(parameter_id)

    def reset_prepared_statement(self, statement_id: int) -> None:
        statement = self.get_prepared_statement(statement_id)
        statement.parameter_types = None
        statement.long_data_parameters.clear()

    def begin_ping(self) -> None:
        self._require_no_pending_lifecycle_operation()
        self.pending_ping = True

    def complete_ping(self, backend_payload: bytes) -> bool:
        if not self.pending_ping:
            raise MySqlProtocolError("No MySQL ping is pending")

        self.pending_ping = False
        if not backend_payload:
            raise MySqlProtocolError("COM_PING backend response is empty")
        if backend_payload[0] == MYSQL_OK_PACKET:
            return True
        if backend_payload[0] == MYSQL_ERR_PACKET:
            return False
        raise MySqlProtocolError(
            "Unexpected backend response to COM_PING"
        )

    def fail_ping(self) -> None:
        self.pending_ping = False

    def begin_statement_reset(self, statement_id: int) -> None:
        self._require_no_pending_lifecycle_operation()
        self.get_prepared_statement(statement_id)
        self.pending_statement_reset_id = statement_id

    def complete_statement_reset(self, backend_payload: bytes) -> bool:
        statement_id = self.pending_statement_reset_id
        if statement_id is None:
            raise MySqlProtocolError(
                "No MySQL statement reset is pending"
            )

        self.pending_statement_reset_id = None
        if not backend_payload:
            raise MySqlProtocolError(
                "COM_STMT_RESET backend response is empty"
            )
        if backend_payload[0] == MYSQL_OK_PACKET:
            self.reset_prepared_statement(statement_id)
            return True
        if backend_payload[0] == MYSQL_ERR_PACKET:
            return False
        raise MySqlProtocolError(
            "Unexpected backend response to COM_STMT_RESET"
        )

    def fail_statement_reset(self) -> None:
        self.pending_statement_reset_id = None

    def begin_command_response(self, kind: str) -> None:
        self._require_no_pending_lifecycle_operation()
        self.pending_command_response = kind
        self.command_response_stage = "initial"
        self.response_columns_remaining = 0

    def fail_command_forward(self) -> None:
        self.pending_command_response = None
        self.command_response_stage = "initial"
        self.response_columns_remaining = 0

    def accept_command_response_packet(
        self,
        backend_payload: bytes,
        *,
        capability_flags: int,
    ) -> None:
        if self.pending_command_response is None:
            raise MySqlProtocolError(
                "Backend command response has no pending client command"
            )
        if not backend_payload:
            self.fail_command_forward()
            raise MySqlProtocolError(
                "Backend command response packet is empty"
            )

        marker = backend_payload[0]
        deprecate_eof = bool(
            capability_flags & CLIENT_DEPRECATE_EOF
        )
        stage = self.command_response_stage

        if marker == MYSQL_ERR_PACKET:
            self.fail_command_forward()
            return

        if stage == "initial":
            if marker == MYSQL_OK_PACKET:
                status = parse_ok_packet_status(
                    backend_payload,
                    capability_flags=capability_flags,
                )
                self.update_transaction_status(status)
                self._finish_or_continue_response(status)
                return
            if marker == 0xFB:
                self.fail_command_forward()
                raise MySqlProtocolError(
                    "LOCAL INFILE responses are not safely tracked"
                )

            (
                self.response_columns_remaining,
                metadata_follows,
            ) = parse_resultset_header(
                backend_payload,
                capability_flags=capability_flags,
            )
            if metadata_follows:
                self.command_response_stage = "metadata"
            else:
                self.response_columns_remaining = 0
                self.command_response_stage = (
                    "rows" if deprecate_eof else "metadata_eof"
                )
            return

        if stage == "metadata":
            if self.response_columns_remaining <= 0:
                self.fail_command_forward()
                raise MySqlProtocolError(
                    "Unexpected result-set metadata packet"
                )
            self.response_columns_remaining -= 1
            if self.response_columns_remaining == 0:
                self.command_response_stage = (
                    "rows" if deprecate_eof else "metadata_eof"
                )
            return

        if stage == "metadata_eof":
            status = parse_eof_packet_status(
                backend_payload,
                capability_flags=capability_flags,
            )
            self.update_transaction_status(status)
            self.command_response_stage = "rows"
            return

        if stage != "rows":
            self.fail_command_forward()
            raise MySqlProtocolError(
                "Unknown backend command-response tracking stage"
            )

        if not deprecate_eof:
            if marker != 0xFE or len(backend_payload) >= 9:
                return
            status = parse_eof_packet_status(
                backend_payload,
                capability_flags=capability_flags,
            )
        else:
            if marker != 0xFE:
                return
            status = parse_ok_packet_status(
                backend_payload,
                capability_flags=capability_flags,
            )

        self.update_transaction_status(status)
        self._finish_or_continue_response(status)

    def _finish_or_continue_response(self, status: int) -> None:
        if status & SERVER_MORE_RESULTS_EXISTS:
            self.command_response_stage = "initial"
            self.response_columns_remaining = 0
            return
        self.fail_command_forward()

    def update_transaction_status(self, status: int) -> None:
        self.server_status_flags = status
        self.transaction_active = bool(
            status & SERVER_STATUS_IN_TRANS
        )
        self.transaction_read_only = bool(
            status & SERVER_STATUS_IN_TRANS_READONLY
        )
        self.autocommit = bool(status & SERVER_STATUS_AUTOCOMMIT)

    def mark_closing(self) -> None:
        self.closing = True
