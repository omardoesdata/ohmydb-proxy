import re
from typing import Optional

from .param_decoder import DecodedParam

_PLACEHOLDER_RE = re.compile(r"\$(\d+)")


def substitute_params(preview_query: str, params: list[DecodedParam]) -> tuple[Optional[str], bool]:
    """Returns (fully-literal SQL with no more placeholders, whether any
    substituted value was only heuristically decoded). Returns (None, False)
    if a referenced parameter couldn't be decoded at all - caller should
    treat the impact estimate as unavailable rather than show a wrong number.
    """
    any_heuristic = False
    failed = False

    def replace(match: "re.Match[str]") -> str:
        nonlocal any_heuristic, failed
        idx = int(match.group(1)) - 1
        if idx >= len(params):
            failed = True
            return match.group(0)
        decoded = params[idx]
        if decoded.confidence == "unknown":
            failed = True
        elif decoded.confidence == "heuristic":
            any_heuristic = True
        return decoded.sql_literal

    result = _PLACEHOLDER_RE.sub(replace, preview_query)
    if failed:
        return None, False
    return result, any_heuristic
