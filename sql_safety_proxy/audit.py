"""Append-only JSONL audit logging for SQL safety decisions."""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .sanitization import bound_external_text, sanitize_sql


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
        max_file_bytes: int = 10 * 1024 * 1024,
        max_backups: int = 3,
        max_field_chars: int = 4096,
    ) -> None:
        if max_file_bytes < 1024:
            raise ValueError("max_file_bytes must be at least 1024")
        if max_backups < 1:
            raise ValueError("max_backups must be at least 1")
        if max_field_chars < 16:
            raise ValueError("max_field_chars must be at least 16")
        self.path = Path(path)
        self.enabled = enabled
        self.max_file_bytes = max_file_bytes
        self.max_backups = max_backups
        self.max_field_chars = max_field_chars
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

        payload = {
            key: (
                bound_external_text(value, max_chars=self.max_field_chars)
                if isinstance(value, str)
                else value
            )
            for key, value in asdict(event).items()
        }
        record = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        ) + "\n"
        self._rotate_if_needed(len(record.encode("utf-8")))

        with self.path.open(
            "a",
            encoding="utf-8",
        ) as handle:
            handle.write(record)

    def _rotate_if_needed(self, incoming_bytes: int) -> None:
        if not self.path.exists():
            return
        if self.path.stat().st_size + incoming_bytes <= self.max_file_bytes:
            return

        oldest = self.path.with_name(
            f"{self.path.name}.{self.max_backups}"
        )
        oldest.unlink(missing_ok=True)
        for index in range(self.max_backups - 1, 0, -1):
            source = self.path.with_name(f"{self.path.name}.{index}")
            if source.exists():
                source.replace(
                    self.path.with_name(f"{self.path.name}.{index + 1}")
                )
        self.path.replace(self.path.with_name(f"{self.path.name}.1"))


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
        sql=sanitize_sql(sql, max_chars=4096),
        database=bound_external_text(database, max_chars=512),
        operation=operation,
        target_table=target_table,
        severity=severity,
        policy_action=policy_action,
        final_decision=final_decision,
        estimated_rows=estimated_rows,
        estimate_error=(
            bound_external_text(estimate_error, max_chars=1024)
            if estimate_error is not None
            else None
        ),
        classification_reason=bound_external_text(
            classification_reason, max_chars=1024
        ),
        policy_reason=bound_external_text(policy_reason, max_chars=1024),
        approximate_estimate=approximate_estimate,
        protocol=protocol,
    )
