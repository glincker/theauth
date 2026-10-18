"""CrewAI guard. ``crewai`` is not imported.

CrewAI tools return strings to the model, so a refusal is returned as a plain
sentence by default (``ToolDenial.to_text``).
"""

from __future__ import annotations

from typing import Any, Optional

from theauth.integrations.gate import FormatDenial, Gate, ToolDenial

__all__ = ["guard_crewai_tool"]


def _text(denial: ToolDenial) -> Any:
    return denial.to_text()


def guard_crewai_tool(
    tool: Any,
    gate: Gate,
    *,
    name: Optional[str] = None,
    format_denial: Optional[FormatDenial] = None,
) -> Any:
    """Guard a CrewAI tool in place and return it.

    Works on a ``BaseTool`` subclass instance (wraps ``_run``) and on a tool made
    with ``@tool`` (wraps ``func``). You can also stack ``@gate.tool(...)`` under
    ``@tool`` on a plain function. The tool name is read from ``tool.name``.
    """
    tool_name = name or str(getattr(tool, "name", None) or "tool")
    fmt = format_denial or _text
    func = getattr(tool, "func", None)
    if callable(func):
        # A `@tool` instance. `func` is a model field, a plain setattr works.
        tool.func = gate.wrap(func, tool_name, format_denial=fmt)
        return tool
    run = getattr(tool, "_run", None)
    if not callable(run):
        raise TypeError("Not a CrewAI tool: expected a `func` or `_run` callable")
    # `_run` is a method on the class; shadow it on the instance (bypasses pydantic checks).
    object.__setattr__(tool, "_run", gate.wrap(run, tool_name, format_denial=fmt))
    return tool
