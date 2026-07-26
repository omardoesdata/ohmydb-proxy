"""Confirmation step is pluggable so the CLI prompt used now can be swapped
for a real popup UI later without touching the proxy logic."""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .sql_classifier import Classification


@dataclass
class QueryContext:
    sql: str
    classification: "Classification"
    estimated_rows: Optional[int] = None
    estimate_error: Optional[str] = None


class ConfirmationProvider(ABC):
    @abstractmethod
    async def confirm(self, ctx: QueryContext) -> bool:
        ...


class CliConfirmationProvider(ConfirmationProvider):
    """Real usage: prompts in the terminal. Will be replaced by the popup UI."""

    async def confirm(self, ctx: QueryContext) -> bool:
        print("\n[sql-safety-proxy] RISKY QUERY DETECTED")
        print(f"  SQL: {ctx.sql}")
        print(f"  Reason: {ctx.classification.reason}")
        if ctx.estimated_rows is not None:
            print(f"  Estimated rows affected: {ctx.estimated_rows}")
        elif ctx.estimate_error:
            print(f"  Could not estimate impact: {ctx.estimate_error}")

        answer = input("  Proceed? [y/N] ")
        return answer.strip().lower() == "y"


class AutoApproveProvider(ConfirmationProvider):
    """Test/automation helper - always approves."""

    async def confirm(self, ctx: QueryContext) -> bool:
        return True


class AutoDenyProvider(ConfirmationProvider):
    """Test/automation helper - always denies."""

    async def confirm(self, ctx: QueryContext) -> bool:
        return False
