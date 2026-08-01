"""MySQL authentication-phase state tracking."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .protocol import (
    MySqlHandshakeResponse,
    MySqlPacket,
    MySqlProtocolError,
)


MYSQL_OK_PACKET = 0x00
MYSQL_AUTH_MORE_DATA = 0x01
MYSQL_AUTH_SWITCH_REQUEST = 0xFE
MYSQL_ERR_PACKET = 0xFF


class MySqlAuthPhase(str, Enum):
    WAITING_FOR_CLIENT_RESPONSE = "waiting_for_client_response"
    AUTHENTICATING = "authenticating"
    AUTHENTICATED = "authenticated"
    FAILED = "failed"
    TLS_REJECTED = "tls_rejected"


class MySqlBackendAuthPacket(str, Enum):
    OK = "ok"
    ERROR = "error"
    AUTH_SWITCH = "auth_switch"
    AUTH_MORE_DATA = "auth_more_data"
    OTHER = "other"


@dataclass
class MySqlAuthState:
    database: str
    phase: MySqlAuthPhase = (
        MySqlAuthPhase.WAITING_FOR_CLIENT_RESPONSE
    )
    username: str | None = None
    capability_flags: int = 0
    auth_plugin: str | None = None
    failure_reason: str | None = None

    @property
    def authenticated(self) -> bool:
        return self.phase == MySqlAuthPhase.AUTHENTICATED

    def accept_client_response(
        self,
        response: MySqlHandshakeResponse,
    ) -> None:
        if self.phase != MySqlAuthPhase.WAITING_FOR_CLIENT_RESPONSE:
            raise MySqlProtocolError(
                "Client handshake response arrived in an invalid "
                f"authentication phase: {self.phase.value}"
            )

        self.capability_flags = response.capability_flags

        if response.is_ssl_request:
            self.phase = MySqlAuthPhase.TLS_REJECTED
            self.failure_reason = (
                "MySQL TLS is unsupported because encrypted SQL "
                "cannot be inspected safely"
            )
            return

        self.username = response.username
        self.auth_plugin = response.auth_plugin

        if response.database:
            self.database = response.database

        self.phase = MySqlAuthPhase.AUTHENTICATING

    def accept_backend_packet(
        self,
        packet: MySqlPacket,
    ) -> MySqlBackendAuthPacket:
        if self.phase != MySqlAuthPhase.AUTHENTICATING:
            raise MySqlProtocolError(
                "Backend authentication packet arrived in an invalid "
                f"authentication phase: {self.phase.value}"
            )

        packet_type = classify_backend_auth_packet(packet)

        if packet_type == MySqlBackendAuthPacket.OK:
            self.phase = MySqlAuthPhase.AUTHENTICATED
            self.failure_reason = None

        elif packet_type == MySqlBackendAuthPacket.ERROR:
            self.phase = MySqlAuthPhase.FAILED
            self.failure_reason = (
                "Backend rejected MySQL authentication"
            )

        return packet_type


def classify_backend_auth_packet(
    packet: MySqlPacket,
) -> MySqlBackendAuthPacket:
    if not packet.payload:
        raise MySqlProtocolError(
            "Backend authentication packet has an empty payload"
        )

    marker = packet.payload[0]

    if marker == MYSQL_OK_PACKET:
        return MySqlBackendAuthPacket.OK

    if marker == MYSQL_ERR_PACKET:
        return MySqlBackendAuthPacket.ERROR

    if marker == MYSQL_AUTH_SWITCH_REQUEST:
        return MySqlBackendAuthPacket.AUTH_SWITCH

    if marker == MYSQL_AUTH_MORE_DATA:
        return MySqlBackendAuthPacket.AUTH_MORE_DATA

    return MySqlBackendAuthPacket.OTHER
