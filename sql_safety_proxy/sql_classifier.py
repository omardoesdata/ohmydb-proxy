"""Dialect-aware SQL classification and read-only impact previews."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import sqlglot
from sqlglot import exp

from .policy import Severity

Dialect = str


@dataclass
class Classification:
    risk: str
    statement_type: str
    reason: str

    preview_query: Optional[str] = None
    impact_kind: str = "unknown"

    target_table: Optional[str] = None
    has_where: Optional[bool] = None
    severity: Severity = Severity.HIGH
    statement_count: int = 1


def classify(
    sql: str,
    dialect: Dialect = "postgres",
) -> Classification:
    try:
        statements = [
            statement
            for statement in sqlglot.parse(sql, read=dialect)
            if statement is not None
        ]
    except Exception as exc:
        return Classification(
            risk="unknown",
            statement_type="UNPARSEABLE",
            reason=f"Could not parse SQL safely: {exc}",
            severity=Severity.HIGH,
            statement_count=0,
        )

    if not statements:
        return Classification(
            risk="unknown",
            statement_type="EMPTY",
            reason="No SQL statement was found",
            severity=Severity.HIGH,
            statement_count=0,
        )

    if len(statements) > 1:
        return Classification(
            risk="risky",
            statement_type="MULTI_STATEMENT",
            reason=(
                f"The request contains {len(statements)} SQL statements; "
                "batch execution requires a dedicated policy decision"
            ),
            impact_kind="batch",
            severity=Severity.CRITICAL,
            statement_count=len(statements),
        )

    ast = statements[0]

    statement_class = type(ast).__name__.upper()

    # Transaction-control statements do not directly mutate rows or schema.
    # They must be forwarded so clients can begin, commit, roll back, and
    # recover transactions through the proxy.
    if statement_class in {
        "TRANSACTION",
        "COMMIT",
        "ROLLBACK",
        "SAVEPOINT",
        "RELEASE",
    }:
        return Classification(
            risk="safe",
            statement_type=statement_class,
            reason="Transaction-control statement",
            impact_kind="transaction",
            severity=Severity.LOW,
        )

    if isinstance(ast, exp.Select):
        return Classification(
            risk="safe",
            statement_type="SELECT",
            reason="Read-only query",
            impact_kind="rows",
            severity=Severity.LOW,
        )

    if isinstance(ast, (exp.Update, exp.Delete)):
        statement_type = "UPDATE" if isinstance(ast, exp.Update) else "DELETE"
        table = ast.find(exp.Table)
        where = ast.find(exp.Where)
        target_table = _table_name(table)
        preview_query = _build_count_query(ast, where, dialect)

        if where is None:
            return Classification(
                risk="risky",
                statement_type=statement_type,
                reason=(
                    f"{statement_type} has no WHERE clause - "
                    "this will affect every row in the target table"
                ),
                preview_query=preview_query,
                impact_kind="rows",
                target_table=target_table,
                has_where=False,
                severity=Severity.CRITICAL,
            )

        return Classification(
            risk="risky",
            statement_type=statement_type,
            reason=(
                f"{statement_type} has a WHERE clause - "
                "review the matching row count before running"
            ),
            preview_query=preview_query,
            impact_kind="rows",
            target_table=target_table,
            has_where=True,
            severity=Severity.MEDIUM,
        )

    if isinstance(ast, exp.TruncateTable):
        table = ast.find(exp.Table)
        preview = (
            exp.select("COUNT(*)").from_(table.copy()).sql(dialect=dialect)
            if table else None
        )
        return Classification(
            risk="risky",
            statement_type="TRUNCATE",
            reason="TRUNCATE removes all rows from the target table",
            preview_query=preview,
            impact_kind="rows",
            target_table=_table_name(table),
            has_where=False,
            severity=Severity.CRITICAL,
        )

    if isinstance(ast, exp.Drop):
        table = ast.find(exp.Table)
        return Classification(
            risk="risky",
            statement_type="DROP",
            reason="DROP is a structural and potentially irreversible change",
            impact_kind="schema",
            target_table=_table_name(table),
            severity=Severity.CRITICAL,
        )

    if isinstance(ast, exp.Alter):
        table = ast.find(exp.Table)
        return Classification(
            risk="risky",
            statement_type="ALTER",
            reason="ALTER changes database structure",
            impact_kind="schema",
            target_table=_table_name(table),
            severity=Severity.HIGH,
        )

    if isinstance(ast, exp.Create):
        table = ast.find(exp.Table)
        return Classification(
            risk="risky",
            statement_type="CREATE",
            reason="CREATE changes database structure",
            impact_kind="schema",
            target_table=_table_name(table),
            severity=Severity.MEDIUM,
        )

    return Classification(
        risk="unknown",
        statement_type=type(ast).__name__.upper(),
        reason="Statement type is not yet covered by a dedicated safety rule",
        severity=Severity.HIGH,
    )

def _table_name(
    table: Optional[exp.Table],
) -> Optional[str]:
    if table is None:
        return None

    return table.sql()


def _build_count_query(
    ast: exp.Expression,
    where: Optional[exp.Where],
    dialect: Dialect,
) -> Optional[str]:
    table = ast.find(exp.Table)

    if table is None:
        return None

    preview = exp.select("COUNT(*)").from_(table.copy())

    if where is not None:
        preview = preview.where(where.this.copy())

    return preview.sql(dialect=dialect)
