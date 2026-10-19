"""Framework guards: authorize a tool call before it runs, fail closed.

Matches the TypeScript helpers in ``packages/core/src/integrations``. No
framework is imported at module import time, so installing ``theauth`` never
pulls in LangGraph, CrewAI or the OpenAI Agents SDK.

::

    from theauth import TheAuthSyncClient
    from theauth.integrations import Gate, guard

    client = TheAuthSyncClient(base_url="https://YOUR_HOST/api/auth")
    gate = Gate.from_token(client, agent_token)

    @guard(gate, "refund")
    def refund(order_id: str, amount: float) -> dict: ...
"""

from theauth.integrations.approval import await_approval, wait_for_approval
from theauth.integrations.crewai import guard_crewai_tool
from theauth.integrations.gate import ApprovalContext, Gate, ToolDenial, is_tool_denial
from theauth.integrations.generic import guard
from theauth.integrations.langgraph import aguard_node, guard_node, guard_tool
from theauth.integrations.openai_agents import guard_function_tool, guard_function_tools

__all__ = [
    "ApprovalContext",
    "Gate",
    "ToolDenial",
    "aguard_node",
    "await_approval",
    "guard",
    "guard_crewai_tool",
    "guard_function_tool",
    "guard_function_tools",
    "guard_node",
    "guard_tool",
    "is_tool_denial",
    "wait_for_approval",
]
