"""Bounded, secret-safe text for logs, audits, and client errors."""

from __future__ import annotations

import re


DEFAULT_MAX_EXTERNAL_TEXT_CHARS = 2048

_DOLLAR_QUOTED = re.compile(
    r"(?s)(\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$).*?\1"
)
_SINGLE_QUOTED = re.compile(r"(?s)'(?:''|\\.|[^'])*'")
_PASSWORD_CLAUSE = re.compile(
    r"(?is)\b(PASSWORD|IDENTIFIED\s+BY)\s+(?:'[^']*'|\"[^\"]*\"|\S+)"
)
_URI_CREDENTIALS = re.compile(
    r"(?i)(\b[a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s@]+(@)"
)


def bound_external_text(
    value: object,
    *,
    max_chars: int = DEFAULT_MAX_EXTERNAL_TEXT_CHARS,
) -> str:
    """Return bounded printable text without control-character log injection."""

    if max_chars < 16:
        raise ValueError("max_chars must be at least 16")
    text = str(value).replace("\r", "\\r").replace("\n", "\\n")
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 14] + "...[truncated]"


def sanitize_sql(
    sql: str,
    *,
    max_chars: int = DEFAULT_MAX_EXTERNAL_TEXT_CHARS,
) -> str:
    """Redact SQL string/password literals before external presentation."""

    sanitized = _DOLLAR_QUOTED.sub("$redacted$", sql)
    sanitized = _SINGLE_QUOTED.sub("'<redacted>'", sanitized)
    sanitized = _PASSWORD_CLAUSE.sub(
        lambda match: f"{match.group(1)} <redacted>", sanitized
    )
    sanitized = _URI_CREDENTIALS.sub(r"\1<redacted>\2", sanitized)
    return bound_external_text(sanitized, max_chars=max_chars)


def safe_exception_summary(exc: BaseException, operation: str) -> str:
    """Describe a failure without copying driver/server exception text."""

    return bound_external_text(
        f"{operation} failed ({type(exc).__name__})",
        max_chars=256,
    )
