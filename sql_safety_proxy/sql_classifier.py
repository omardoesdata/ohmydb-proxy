"""Dialect-aware SQL risk classification and read-only impact previews.

The classifier is database-agnostic: sqlglot parses the configured dialect and
we produce SELECT-based preview SQL. Execution of that preview belongs to a
separate database adapter.
"""
from dataclasses import dataclass
from typing import Optional

import sqlglot
from sqlglot import exp

Dialect = str


@dataclass
class Classification:
    risk: str  # "safe" | "risky" | "unknown"
    statement_type: str
    reason: str
    preview_query: Optional[str] = None
    impact_kind: str = "unknown"  # rows | schema | permissions | unknown


def classify(sql: str, dialect: Dialect = "postgres") -> Classification:
    try:
        ast = sqlglot.parse_one(sql, read=dialect)
    except Exception as exc:
        return Classification(
            risk="unknown",
            statement_type="unparseable",
            reason=f"Could not parse SQL safely: {exc}",
        )

    if isinstance(ast, exp.Select):
        return Classification("safe", "SELECT", "Read-only query", impact_kind="rows")

    if isinstance(ast, (exp.Update, exp.Delete)):
        stmt_type = "UPDATE" if isinstance(ast, exp.Update) else "DELETE"
        where = ast.find(exp.Where)
        preview_query = _build_count_query(ast, where, dialect)
        if where is None:
            return Classification(
                risk="risky",
                statement_type=stmt_type,
                reason=f"{stmt_type} has no WHERE clause - this will affect every row in the target table",
                preview_query=preview_query,
                impact_kind="rows",
            )
        return Classification(
            risk="risky",
            statement_type=stmt_type,
            reason=f"{stmt_type} has a WHERE clause - review the matching row count before running",
            preview_query=preview_query,
            impact_kind="rows",
        )

    if isinstance(ast, exp.TruncateTable):
        table = ast.find(exp.Table)
        preview = exp.select("COUNT(*)").from_(table.copy()).sql(dialect=dialect) if table else None
        return Classification(
            "risky", "TRUNCATE", "TRUNCATE removes all rows from the target table",
            preview_query=preview, impact_kind="rows",
        )

    if isinstance(ast, exp.Drop):
        return Classification(
            "risky", "DROP", "DROP is a structural and potentially irreversible change",
            impact_kind="schema",
        )

    if isinstance(ast, (exp.Alter, exp.Create)):
        return Classification(
            "risky", type(ast).__name__.upper(),
            "This statement changes database structure",
            impact_kind="schema",
        )

    # Unknown statements are not silently called safe. The proxy currently
    # forwards them, but the classification is visible for future policy modes.
    return Classification(
        risk="unknown",
        statement_type=type(ast).__name__,
        reason="Statement type is not yet covered by a dedicated safety rule",
    )


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
