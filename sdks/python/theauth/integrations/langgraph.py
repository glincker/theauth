"""LangGraph guards. Neither ``langgraph`` nor ``langchain`` is imported.

* :func:`guard_tool` wraps a tool function, so a refusal becomes the tool result
  and the graph continues.
* :func:`guard_node` wraps a node that executes tool calls (for example the
  prebuilt ``ToolNode``) and checks every pending call first.
"""

from __future__ import annotations

import inspect
from typing import Any, Callable, Dict, List, Optional, Tuple

from theauth.integrations.gate import F, FormatDenial, Gate, ToolDenial

__all__ = ["aguard_node", "guard_node", "guard_tool"]

SKIPPED_REASON = (
    "Not run because another tool call in the same step was refused. Call it again on its own."
)


def guard_tool(
    gate: Gate, fn: F, name: Optional[str] = None, *, format_denial: Optional[FormatDenial] = None
) -> F:
    """Wrap one tool function. Pass the result to ``StructuredTool.from_function``."""
    return gate.wrap(fn, name, format_denial=format_denial)


def _get(obj: Any, key: str) -> Any:
    return obj.get(key) if isinstance(obj, dict) else getattr(obj, key, None)


def _pending_calls(state: Any, messages_key: str) -> List[Tuple[str, Any, Optional[str]]]:
    messages = _get(state, messages_key)
    if not messages:
        return []
    calls = _get(messages[-1], "tool_calls") or []
    return [(str(_get(c, "name")), _get(c, "args"), _get(c, "id")) for c in calls]


def _tool_message(call_id: Optional[str], name: str, denial: ToolDenial) -> Dict[str, Any]:
    # LangGraph's message reducer turns a role "tool" dict into a ToolMessage.
    return {"role": "tool", "name": name, "tool_call_id": call_id, "content": denial.to_json()}


def _refusals(
    calls: List[Tuple[str, Any, Optional[str]]],
    denials: List[Optional[ToolDenial]],
    messages_key: str,
) -> Optional[Dict[str, Any]]:
    if not any(denials):
        return None
    out: List[Dict[str, Any]] = []
    for (name, _args, call_id), denial in zip(calls, denials):
        out.append(
            _tool_message(call_id, name, denial or ToolDenial(name, "skipped", SKIPPED_REASON))
        )
    return {messages_key: out}


def _accepts_config(node: Any) -> bool:
    try:
        return "config" in inspect.signature(node).parameters
    except (TypeError, ValueError):
        return False


def _is_runnable(node: Any) -> bool:
    return not inspect.isfunction(node) and callable(getattr(node, "invoke", None))


def _typed(fn: F) -> F:
    """Give ``config`` the ``RunnableConfig`` annotation when langchain is installed.

    LangGraph warns about an untyped ``config``. The import happens here, at
    call time, so ``theauth`` still never needs langchain.
    """
    try:
        from langchain_core.runnables import RunnableConfig

        fn.__annotations__["config"] = Optional[RunnableConfig]
    except Exception:
        pass
    return fn


def guard_node(node: Any, gate: Gate, *, messages_key: str = "messages") -> Callable[..., Any]:
    """Wrap a graph node that runs the tool calls of the last AI message.

    ``node`` is a function ``(state)`` or ``(state, config)``, sync or async, or
    a LangGraph runnable such as ``ToolNode`` (called through ``invoke``). Use
    :func:`aguard_node` for a runnable in an async graph.

    Each pending call is checked before the node runs. If every call is allowed
    the node runs as usual. If any is refused the node does not run, and the
    update holds a tool message per call: the denial JSON for refused calls and
    a ``skipped`` notice for the others, so every ``tool_call_id`` still gets an
    answer. A state without tool calls passes straight through. The ``config``
    LangGraph passes in is the context given to ``agent_id`` when that is a
    function.
    """
    if inspect.iscoroutinefunction(node):
        return _async_node(node, gate, messages_key, lambda s, c: node(s, c) if _accepts_config(node) else node(s))
    runnable = _is_runnable(node)
    with_config = _accepts_config(node)

    def snode(state: Any, config: Any = None) -> Any:
        calls = _pending_calls(state, messages_key)
        denials = [gate.check(n, a, config) for n, a, _ in calls]
        refused = _refusals(calls, denials, messages_key)
        if refused is not None:
            return refused
        if runnable:
            return node.invoke(state, config)
        return node(state, config) if with_config else node(state)

    return _typed(snode)


def aguard_node(node: Any, gate: Gate, *, messages_key: str = "messages") -> Callable[..., Any]:
    """Async twin of :func:`guard_node`. A runnable is called through ``ainvoke``."""
    if _is_runnable(node):
        return _async_node(node, gate, messages_key, lambda s, c: node.ainvoke(s, c))
    return guard_node(node, gate, messages_key=messages_key)


def _async_node(
    node: Any, gate: Gate, messages_key: str, call: Callable[[Any, Any], Any]
) -> Callable[..., Any]:
    async def anode(state: Any, config: Any = None) -> Any:
        calls = _pending_calls(state, messages_key)
        denials = [await gate.acheck(n, a, config) for n, a, _ in calls]
        refused = _refusals(calls, denials, messages_key)
        return refused if refused is not None else await call(state, config)

    return _typed(anode)
