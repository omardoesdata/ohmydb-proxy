"""Classifies a SQL statement's risk level and builds a safe COUNT(*) preview
query for UPDATE/DELETE statements, so we can show real impact before the
mutation runs.
"""
from dataclasses import dataclass
from typing import Optional

import sqlglot
from sqlglot import exp

Dialect = str  # sqlglot dialect key: "postgres", "mysql", "sqlite", "tsql", etc.


@dataclass
class Classification:
    risk: str  # "safe" | "risky" | "unknown"
    statement_type: str
    reason: str
    preview_query: Optional[str] = None


def classify(sql: str, dialect: Dialect = "postgres") -> Classification:
    try:
        ast = sqlglot.parse_one(sql, read=dialect)
    except Exception as e:
        # Can't safely reason about SQL we can't parse - treat conservatively.
        return Classification(risk="unknown", statement_type="unparseable",
                               reason=f"Could not parse SQL: {e}")

    if isinstance(ast, exp.Select):
        return Classification(risk="safe", statement_type="SELECT", reason="Read-only query")

    if isinstance(ast, (exp.Update, exp.Delete)):
        stmt_type = "UPDATE" if isinstance(ast, exp.Update) else "DELETE"
        where = ast.find(exp.Where)
        if where is None:
            return Classification(
                risk="risky",
                statement_type=stmt_type,
                reason=f"{stmt_type} has no WHERE clause - this will affect every row in the table",
            )
        preview_query = _build_count_query(ast, where, dialect)
        return Classification(
            risk="risky",
            statement_type=stmt_type,
            reason=f"{stmt_type} has a WHERE clause - confirming affected row count before running",
            preview_query=preview_query,
        )

    if isinstance(ast, exp.Drop):
        return Classification(risk="risky", statement_type="DROP",
                               reason="DROP is a structural, irreversible change")

    if isinstance(ast, exp.TruncateTable):
        return Classification(risk="risky", statement_type="TRUNCATE",
                               reason="TRUNCATE is a structural, irreversible change")

    return Classification(risk="safe", statement_type=type(ast).__name__,
                           reason="Not a recognized mutation type")


def _build_count_query(ast: exp.Expression, where: exp.Where, dialect: Dialect) -> str:
    table = ast.find(exp.Table)
    preview = exp.select("COUNT(*)").from_(table.copy())
    preview = preview.where(where.this.copy())
    return preview.sql(dialect=dialect)
