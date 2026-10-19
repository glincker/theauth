"""Run the Python snippets of docs/integrations/langgraph-crewai.mdx against a fake server.

The blocks run in order in one namespace, with the framework packages replaced by
tiny fakes, so the page cannot drift from the SDK. Real frameworks are covered in
test_integrations_real.py when they are installed.
"""

from __future__ import annotations

import dataclasses
import json
import re
import sys
import types
from pathlib import Path
from typing import Any, Callable, Dict, List

import httpx
import pytest
import respx

DOC = Path(__file__).resolve().parents[3] / "docs" / "integrations" / "langgraph-crewai.mdx"
AUTH = "https://auth.example.test/api/auth"
APP = "https://app.example.test/api/open-approval"


def python_blocks(text: str) -> List[str]:
    return re.findall(r"```python\n(.*?)```", text, flags=re.S)


def install_fake_frameworks(monkeypatch: pytest.MonkeyPatch) -> None:
    def module(name: str, **attrs: Any) -> types.ModuleType:
        mod = types.ModuleType(name)
        for key, value in attrs.items():
            setattr(mod, key, value)
        monkeypatch.setitem(sys.modules, name, mod)
        return mod

    class StructuredTool:
        def __init__(self, func: Callable[..., Any], name: str, description: str) -> None:
            self.func, self.name, self.description = func, name, description

        @classmethod
        def from_function(cls, func: Callable[..., Any], name: str, description: str) -> Any:
            return cls(func, name, description)

    class ToolNode:
        def __init__(self, tools: List[Any]) -> None:
            self.tools = tools

        def invoke(self, state: Dict[str, Any], config: Any = None) -> Dict[str, Any]:
            return {"messages": ["ran"]}

    class CrewTool:
        def __init__(self, name: str, func: Callable[..., Any]) -> None:
            self.name, self.func = name, func

    def crew_tool(name: str) -> Callable[[Callable[..., Any]], CrewTool]:
        return lambda fn: CrewTool(name, fn)

    @dataclasses.dataclass
    class FunctionTool:
        name: str
        on_invoke_tool: Callable[..., Any]

    def function_tool(fn: Callable[..., Any]) -> FunctionTool:
        async def invoke(_ctx: Any, input_json: str) -> Any:
            return fn(**json.loads(input_json))

        return FunctionTool(fn.__name__, invoke)

    module("langchain_core")
    module("langchain_core.tools", StructuredTool=StructuredTool)
    module("langgraph")
    module("langgraph.prebuilt", ToolNode=ToolNode)
    module("crewai")
    module("crewai.tools", tool=crew_tool)
    module("agents", function_tool=function_tool)


def fake_server() -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer ta_agent_secret"
        body = json.loads(request.content)
        args = body.get("arguments") or {}
        if body.get("approvalId") == "ap1" or args.get("amount", 0) <= 50:
            return httpx.Response(200, json={"data": {"allowed": True, "auditId": "aud_1"}})
        return httpx.Response(
            403,
            json={
                "data": {
                    "allowed": False,
                    "code": "approval_required",
                    "reason": "approval required for tool:refund",
                    "auditId": "aud_2",
                }
            },
        )

    return handler


@pytest.fixture
def doc_namespace(monkeypatch: pytest.MonkeyPatch) -> Any:
    install_fake_frameworks(monkeypatch)
    monkeypatch.setenv("THEAUTH_URL", AUTH)
    monkeypatch.setenv("THEAUTH_AGENT_TOKEN", "ta_agent_secret")
    monkeypatch.setenv("THEAUTH_ADMIN_TOKEN", "ta_admin_secret")
    monkeypatch.setenv("APPROVAL_OPENER_URL", APP)
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{AUTH}/authorize/token").mock(side_effect=fake_server())
        router.get(f"{AUTH}/approvals/ap1").mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "id": "ap1",
                        "status": "approved",
                        "action": "execute",
                        "resource": "tool:refund",
                        "expiresAt": "2030-01-01T00:00:00Z",
                    }
                },
            )
        )
        router.post(APP).mock(return_value=httpx.Response(200, json={"id": "ap1"}))
        namespace: Dict[str, Any] = {"__name__": "docs_snippet"}
        for index, block in enumerate(python_blocks(DOC.read_text())):
            exec(compile(block, f"{DOC.name}#python{index}", "exec"), namespace)
        yield namespace


def test_page_has_runnable_python_blocks() -> None:
    assert len(python_blocks(DOC.read_text())) == 7


def test_langgraph_snippets(doc_namespace: Dict[str, Any]) -> None:
    tool = doc_namespace["refund_tool"]
    assert tool.name == "refund"
    assert tool.func(order_id="o1", amount=40) == {"order_id": "o1", "refunded": 40}
    refused = tool.func(order_id="o1", amount=400)
    assert refused["denied"] is True
    assert refused["code"] == "approval_required"
    assert refused["approvalRequired"] is True
    node = doc_namespace["tool_node"]
    call = {"name": "refund", "args": {"order_id": "o", "amount": 400}, "id": "c1"}
    out = node({"messages": [{"tool_calls": [call]}]}, None)
    assert json.loads(out["messages"][0]["content"])["code"] == "approval_required"
    ok = {"name": "refund", "args": {"order_id": "o", "amount": 4}, "id": "c2"}
    assert node({"messages": [{"tool_calls": [ok]}]}, None) == {"messages": ["ran"]}


def test_crewai_snippet(doc_namespace: Dict[str, Any]) -> None:
    tool = doc_namespace["refund_order"]
    assert tool.func(order_id="o", amount=10) == "Refunded 10 on o"
    assert tool.func(order_id="o", amount=900).startswith("Refused (approval_required)")


async def test_openai_agents_snippet(doc_namespace: Dict[str, Any]) -> None:
    tool = doc_namespace["lookup_invoice"]
    assert await tool.on_invoke_tool(None, json.dumps({"invoice_id": "inv_1"})) == "inv_1: paid"


def test_generic_snippet(doc_namespace: Dict[str, Any]) -> None:
    assert doc_namespace["send_email"]("a@example.com", "hi") == "sent to a@example.com"


def test_approval_snippet_retries_with_approved_id(doc_namespace: Dict[str, Any]) -> None:
    gate = doc_namespace["gate"]
    assert gate.check("refund", {"order_id": "o", "amount": 500}) is None
