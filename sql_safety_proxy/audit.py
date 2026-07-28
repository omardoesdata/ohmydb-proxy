"""Append-only JSONL audit logging for SQL safety decisions."""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class AuditEvent:
    timestamp: str
    sql: str
    database: str
    operation: str
    target_table: Optional[str]
    severity: str
    policy_action: str
    final_decision: str
    estimated_rows: Optional[int]
    estimate_error: Optional[str]
    classification_reason: str
    policy_reason: str
    approximate_estimate: bool
    protocol: str


class JsonlAuditLogger:
    """Serialize append-only JSONL writes outside the asyncio event loop."""

    def __init__(
        self,
        path: str | Path,
        enabled: bool = True,
    ) -> None:
        self.path = Path(path)
        self.enabled = enabled
        self._lock = asyncio.Lock()

    async def log(self, event: AuditEvent) -> None:
        if not self.enabled:
            return

        async with self._lock:
            await asyncio.to_thread(
                self._append,
                event,
            )

    def _append(self, event: AuditEvent) -> None:
        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with self.path.open(
            "a",
            encoding="utf-8",
        ) as handle:
            handle.write(
                json.dumps(
                    asdict(event),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            )
            handle.write("\n")


def build_audit_event(
    *,
    sql: str,
    database: str,
    operation: str,
    target_table: Optional[str],
    severity: str,
    policy_action: str,
    final_decision: str,
    estimated_rows: Optional[int],
    estimate_error: Optional[str],
    classification_reason: str,
    policy_reason: str,
    approximate_estimate: bool,
    protocol: str,
) -> AuditEvent:
    return AuditEvent(
        timestamp=datetime.now(timezone.utc).isoformat(),
        sql=sql,
        database=database,
        operation=operation,
        target_table=target_table,
        severity=severity,
        policy_action=policy_action,
        final_decision=final_decision,
        estimated_rows=estimated_rows,
        estimate_error=estimate_error,
        classification_reason=classification_reason,
        policy_reason=policy_reason,
        approximate_estimate=approximate_estimate,
        protocol=protocol,
    )
