"""Authenticated MySQL session state."""

from __future__ import annotations

from dataclasses import dataclass, field

from .protocol import MySqlProtocolError


MYSQL_OK_PACKET = 0x00
MYSQL_ERR_PACKET = 0xFF


@dataclass(frozen=True)
class MySqlPreparedStatement:
    statement_id: int
    sql: str
    parameter_count: int
    column_count: int


@dataclass
class MySqlSessionState:
    database: str
    pending_database: str | None = None
    pending_statement_sql: str | None = None
    prepared_statements: dict[int, MySqlPreparedStatement] = field(
        default_factory=dict
    )
    closing: bool = False

    def begin_database_change(self, database: str) -> None:
        normalized = database.strip()

        if not normalized:
            raise MySqlProtocolError(
                "COM_INIT_DB database name cannot be empty"
            )

        if self.pending_database is not None:
            raise MySqlProtocolError(
                "A MySQL database change is already pending"
            )

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

        if self.pending_statement_sql is not None:
            raise MySqlProtocolError(
                "A MySQL statement prepare is already pending"
            )

        self.pending_statement_sql = normalized

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

        statement = MySqlPreparedStatement(
            statement_id=statement_id,
            sql=self.pending_statement_sql,
            parameter_count=parameter_count,
            column_count=column_count,
        )

        self.prepared_statements[statement_id] = statement
        self.pending_statement_sql = None
        return statement

    def fail_statement_prepare(self) -> None:
        self.pending_statement_sql = None

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
        return self.prepared_statements.pop(
            statement_id,
            None,
        )

    def mark_closing(self) -> None:
        self.closing = True
