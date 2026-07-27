"""Pluggable confirmation providers for SQL safety decisions."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .policy import PolicyDecision
    from .sql_classifier import Classification


@dataclass
class QueryContext:
    sql: str
    classification: "Classification"
    estimated_rows: Optional[int] = None
    estimate_error: Optional[str] = None
    policy_decision: Optional["PolicyDecision"] = None
    database: Optional[str] = None
    approximate_estimate: bool = False


class ConfirmationProvider(ABC):
    @abstractmethod
    async def confirm(self, ctx: QueryContext) -> bool:
        ...


class CliConfirmationProvider(ConfirmationProvider):
    async def confirm(self, ctx: QueryContext) -> bool:
        print("\n[sql-safety-proxy] QUERY CONFIRMATION REQUIRED")
        print(f"  SQL: {ctx.sql}")
        print(f"  Operation: {ctx.classification.statement_type}")
        print(f"  Table: {ctx.classification.target_table or 'unknown'}")

        if ctx.database:
            print(f"  Database: {ctx.database}")

        if ctx.policy_decision:
            print(f"  Severity: {ctx.policy_decision.severity.value}")
            print(f"  Policy: {ctx.policy_decision.action.value}")
            print(f"  Policy reason: {ctx.policy_decision.reason}")

        print(f"  Classification reason: {ctx.classification.reason}")

        if ctx.estimated_rows is not None:
            suffix = " (approximate)" if ctx.approximate_estimate else ""
            print(f"  Estimated rows affected: {ctx.estimated_rows}{suffix}")
        elif ctx.estimate_error:
            print(f"  Could not estimate impact: {ctx.estimate_error}")

        answer = input("  Proceed? [y/N] ")
        return answer.strip().lower() == "y"


class AutoApproveProvider(ConfirmationProvider):
    async def confirm(self, ctx: QueryContext) -> bool:
        return True


class AutoDenyProvider(ConfirmationProvider):
    async def confirm(self, ctx: QueryContext) -> bool:
        return False
