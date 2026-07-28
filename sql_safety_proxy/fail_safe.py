"""Fail-safe handling for PostgreSQL protocol states the proxy cannot inspect."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FailSafeMode(str, Enum):
    STRICT = "strict"
    BALANCED = "balanced"
    PERMISSIVE = "permissive"


class ProtocolGapAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class ProtocolGapDecision:
    action: ProtocolGapAction
    reason: str


def evaluate_protocol_gap(
    mode: FailSafeMode,
    reason: str,
) -> ProtocolGapDecision:
    """Decide whether uninspectable protocol traffic may reach PostgreSQL."""

    if mode == FailSafeMode.PERMISSIVE:
        return ProtocolGapDecision(
            action=ProtocolGapAction.ALLOW,
            reason=(
                f"{reason}; permissive fail-safe mode allows forwarding"
            ),
        )

    return ProtocolGapDecision(
        action=ProtocolGapAction.BLOCK,
        reason=(
            f"{reason}; {mode.value} fail-safe mode blocks uninspectable SQL"
        ),
    )
