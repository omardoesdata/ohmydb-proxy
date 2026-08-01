"""Authenticated MySQL session state."""

from __future__ import annotations

from dataclasses import dataclass

from .protocol import MySqlProtocolError


MYSQL_OK_PACKET = 0x00
MYSQL_ERR_PACKET = 0xFF


@dataclass
class MySqlSessionState:
    database: str
    pending_database: str | None = None
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

    def mark_closing(self) -> None:
        self.closing = True
