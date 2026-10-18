"""Generic decorator for any Python tool function."""

from __future__ import annotations

from typing import Callable, Optional

from theauth.integrations.gate import F, FormatDenial, Gate


def guard(
    gate: Gate,
    name: Optional[str] = None,
    *,
    format_denial: Optional[FormatDenial] = None,
) -> Callable[[F], F]:
    """Decorator: run ``gate`` before the function, return the denial dict if refused.

    ::

        @guard(gate, "refund")
        def refund(order_id: str, amount: float) -> dict: ...

    Works on sync and async functions and keeps the signature and docstring.
    """
    return gate.tool(name, format_denial=format_denial)
