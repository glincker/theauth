"""OpenAI Agents SDK guard. The ``agents`` package is not imported.

``@function_tool`` returns a ``FunctionTool`` whose ``on_invoke_tool(ctx, input_json)``
is what the runner calls. The guard wraps that, parses ``input_json`` for the
argument check, and returns the denial JSON as the tool output.
"""

from __future__ import annotations

import copy
import dataclasses
import functools
import json
from typing import Any, List, Optional, Sequence, TypeVar

from theauth.integrations.gate import FormatDenial, Gate, ToolDenial

__all__ = ["guard_function_tool", "guard_function_tools"]

T = TypeVar("T")


def _json_text(denial: ToolDenial) -> Any:
    return denial.to_json()


def guard_function_tool(
    tool: T,
    gate: Gate,
    *,
    name: Optional[str] = None,
    format_denial: Optional[FormatDenial] = None,
) -> T:
    """Return a copy of a ``FunctionTool`` that checks ``gate`` before running.

    The run context wrapper is passed to ``agent_id`` as ``ctx`` when that is a
    function. Invalid input JSON is refused (code ``guard_error``) instead of
    being checked as if it had no arguments.
    """
    original = getattr(tool, "on_invoke_tool", None)
    if not callable(original):
        raise TypeError("Not an OpenAI Agents FunctionTool: missing on_invoke_tool")
    tool_name = name or str(getattr(tool, "name", None) or "tool")
    fmt = format_denial or _json_text

    @functools.wraps(original)
    async def on_invoke_tool(ctx: Any, input_json: str) -> Any:
        try:
            parsed = json.loads(input_json) if input_json else {}
        except (TypeError, ValueError):
            refusal = ToolDenial(tool_name, "guard_error", "Tool input is not valid JSON")
            return fmt(refusal)
        if not isinstance(parsed, dict):
            parsed = {"input": parsed}
        refused = await gate.acheck(tool_name, parsed, ctx)
        if refused:
            return fmt(refused)
        result = original(ctx, input_json)
        if hasattr(result, "__await__"):
            return await result
        return result

    if dataclasses.is_dataclass(tool) and not isinstance(tool, type):
        return dataclasses.replace(tool, on_invoke_tool=on_invoke_tool)
    clone = copy.copy(tool)
    clone.on_invoke_tool = on_invoke_tool  # type: ignore[attr-defined]
    return clone


def guard_function_tools(
    tools: Sequence[T], gate: Gate, *, format_denial: Optional[FormatDenial] = None
) -> List[T]:
    """Guard a list of function tools with the same gate."""
    return [guard_function_tool(t, gate, format_denial=format_denial) for t in tools]
