"""Configurable safety policy for classified SQL statements."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .sql_classifier import Classification


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    CONFIRM = "CONFIRM"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class PolicyConfig:
    """Thresholds controlling how risky queries are handled."""

    auto_allow_max_rows: int = 0
    block_at_rows: int = 10_000

    no_where_action: PolicyAction = PolicyAction.CONFIRM
    structural_action: PolicyAction = PolicyAction.CONFIRM
    unknown_action: PolicyAction = PolicyAction.CONFIRM
    estimation_failure_action: PolicyAction = PolicyAction.CONFIRM

    def __post_init__(self) -> None:
        if self.auto_allow_max_rows < 0:
            raise ValueError("auto_allow_max_rows cannot be negative")

        if self.block_at_rows <= self.auto_allow_max_rows:
            raise ValueError(
                "block_at_rows must be greater than auto_allow_max_rows"
            )


@dataclass(frozen=True)
class PolicyDecision:
    action: PolicyAction
    severity: Severity
    reason: str
    estimated_rows: Optional[int] = None


def evaluate_policy(
    classification: "Classification",
    estimated_rows: Optional[int],
    estimate_error: Optional[str],
    config: PolicyConfig,
) -> PolicyDecision:
    """Evaluate one classified statement against the configured policy."""

    if classification.risk == "safe":
        return PolicyDecision(
            action=PolicyAction.ALLOW,
            severity=Severity.LOW,
            reason="Read-only statement",
            estimated_rows=estimated_rows,
        )

    if classification.risk == "unknown":
        return PolicyDecision(
            action=config.unknown_action,
            severity=Severity.HIGH,
            reason=(
                "No dedicated safety rule exists for this statement type; "
                "the unknown-query policy was applied"
            ),
            estimated_rows=estimated_rows,
        )

    if classification.impact_kind == "schema":
        return PolicyDecision(
            action=config.structural_action,
            severity=Severity.CRITICAL,
            reason=(
                "This statement changes database structure; "
                "the structural-query policy was applied"
            ),
            estimated_rows=estimated_rows,
        )

    if classification.has_where is False:
        return PolicyDecision(
            action=config.no_where_action,
            severity=Severity.CRITICAL,
            reason=(
                f"{classification.statement_type} has no WHERE clause and "
                "may affect the entire target table"
            ),
            estimated_rows=estimated_rows,
        )

    if estimate_error or estimated_rows is None:
        return PolicyDecision(
            action=config.estimation_failure_action,
            severity=Severity.HIGH,
            reason=(
                "Affected-row estimation was unavailable; "
                "the estimation-failure policy was applied"
            ),
            estimated_rows=None,
        )

    if estimated_rows >= config.block_at_rows:
        return PolicyDecision(
            action=PolicyAction.BLOCK,
            severity=Severity.CRITICAL,
            reason=(
                f"Estimated impact of {estimated_rows} rows meets or exceeds "
                f"the block threshold of {config.block_at_rows}"
            ),
            estimated_rows=estimated_rows,
        )

    if estimated_rows <= config.auto_allow_max_rows:
        return PolicyDecision(
            action=PolicyAction.ALLOW,
            severity=Severity.LOW,
            reason=(
                f"Estimated impact of {estimated_rows} rows is within the "
                f"automatic-allow threshold of {config.auto_allow_max_rows}"
            ),
            estimated_rows=estimated_rows,
        )

    severity = (
        Severity.MEDIUM
        if estimated_rows < 100
        else Severity.HIGH
    )

    return PolicyDecision(
        action=PolicyAction.CONFIRM,
        severity=severity,
        reason=(
            f"Estimated impact of {estimated_rows} rows requires explicit "
            "confirmation"
        ),
        estimated_rows=estimated_rows,
    )
