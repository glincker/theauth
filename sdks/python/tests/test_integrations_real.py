"""The guards against the real frameworks. Skipped when a framework is not installed."""

from __future__ import annotations

import json
from typing import Any, Optional

import pytest

from theauth.integrations import Gate, guard, guard_crewai_tool, guard_function_tool, guard_node, guard_tool
from theauth.types import AuthorizeRequest, AuthorizeResult


def authorize(_agent_id: str, request: AuthorizeRequest) -> AuthorizeResult:
    args = request.arguments or {}
    ok = args.get("amount", 0) <= 50
    return AuthorizeResult(
        allowed=ok,
        audit_id="aud",
        reason=None if ok else "needs a human",
        code=None if ok else "approval_required",
    )


gate = Gate(authorize, "agent-1")


def test_langgraph_tool_and_node() -> None:
    pytest.importorskip("langgraph")
    from langchain_core.messages import AIMessage
    from langchain_core.tools import StructuredTool
    from langgraph.graph import END, START, MessagesState, StateGraph
    from langgraph.prebuilt import ToolNode

    def refund(order_id: str, amount: float) -> dict[str, Any]:
        """Refund an order."""
        return {"order": order_id, "refunded": amount}

    tool = StructuredTool.from_function(
        func=guard_tool(gate, refund, "refund"), name="refund", description="Refund an order"
    )
    assert set(tool.args) == {"order_id", "amount"}
    assert tool.invoke({"order_id": "o", "amount": 10})["refunded"] == 10
    assert tool.invoke({"order_id": "o", "amount": 500})["code"] == "approval_required"

    builder = StateGraph(MessagesState)
    builder.add_node("tools", guard_node(ToolNode([tool]), gate))
    builder.add_edge(START, "tools")
    builder.add_edge("tools", END)
    app = builder.compile()

    def run(amount: float) -> Any:
        call = {"name": "refund", "args": {"order_id": "o", "amount": amount}, "id": "c1"}
        return app.invoke({"messages": [AIMessage(content="", tool_calls=[call])]})["messages"][-1]

    assert json.loads(run(10).content)["refunded"] == 10
    refused = run(500)
    assert refused.tool_call_id == "c1"
    assert json.loads(refused.content)["code"] == "approval_required"


def test_crewai_tools() -> None:
    pytest.importorskip("crewai")
    from crewai.tools import BaseTool, tool

    @tool("refund")
    @guard(gate, "refund", format_denial=lambda d: d.to_text())
    def refund(order_id: str, amount: float) -> str:
        """Refund an order."""
        return f"Refunded {amount}"

    assert refund.run(order_id="o", amount=10) == "Refunded 10"
    assert refund.run(order_id="o", amount=500).startswith("Refused (approval_required)")

    class Search(BaseTool):
        name: str = "search"
        description: str = "Search"

        def _run(self, amount: float) -> str:
            return "found"

    guarded = guard_crewai_tool(Search(), gate)
    assert guarded.run(amount=1) == "found"
    assert guarded.run(amount=500).startswith("Refused (approval_required)")


async def test_openai_agents_function_tool() -> None:
    pytest.importorskip("agents")
    from agents import Agent, function_tool
    from agents.tool_context import ToolContext

    @function_tool
    def refund(order_id: str, amount: float) -> str:
        """Refund an order."""
        return "done"

    guarded = guard_function_tool(refund, gate)
    Agent(name="a", tools=[guarded])

    def ctx(args: str) -> Any:
        return ToolContext(context=None, tool_name="refund", tool_call_id="c", tool_arguments=args)

    ok = json.dumps({"order_id": "o", "amount": 10})
    no = json.dumps({"order_id": "o", "amount": 500})
    assert await guarded.on_invoke_tool(ctx(ok), ok) == "done"
    assert json.loads(await guarded.on_invoke_tool(ctx(no), no))["code"] == "approval_required"
    bad: Optional[str] = "{nope"
    assert json.loads(await guarded.on_invoke_tool(ctx(bad or ""), bad or ""))["code"] == "guard_error"
