"""Gate, approval wait and framework guards, with fake frameworks (no framework installed)."""

from __future__ import annotations

import dataclasses
import json
import subprocess
import sys
from typing import Any, Dict, List, Optional

import httpx
import pytest
import respx

from theauth import TheAuthClient, TheAuthSyncClient
from theauth.approvals import ApprovalState
from theauth.integrations import (
    ApprovalContext,
    Gate,
    ToolDenial,
    aguard_node,
    await_approval,
    guard,
    guard_crewai_tool,
    guard_function_tool,
    guard_function_tools,
    guard_node,
    guard_tool,
    is_tool_denial,
    wait_for_approval,
)
from theauth.types import AuthorizeRequest, AuthorizeResult

BASE = "https://t.example.test/api/auth"


def result(allowed: bool, code: Optional[str] = None, reason: Optional[str] = None) -> AuthorizeResult:
    return AuthorizeResult(allowed=allowed, audit_id="aud", reason=reason, code=code)  # type: ignore[arg-type]


class Recorder:
    """An authorize function that records calls and answers from a script."""

    def __init__(self, *answers: Any) -> None:
        self.answers = list(answers)
        self.calls: List[AuthorizeRequest] = []
        self.agent_ids: List[str] = []

    def __call__(self, agent_id: str, request: AuthorizeRequest) -> Any:
        self.agent_ids.append(agent_id)
        self.calls.append(request)
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, Exception):
            raise answer
        return answer


# gate


def test_allowed_returns_none_and_sends_default_resource() -> None:
    rec = Recorder(result(True))
    gate = Gate(rec, "agent-1")
    assert gate.check("refund", {"amount": 3}) is None
    assert rec.calls[0].action == "execute"
    assert rec.calls[0].resource == "tool:refund"
    assert rec.calls[0].arguments == {"amount": 3}
    assert rec.agent_ids == ["agent-1"]


def test_denial_carries_code_reason_audit_and_approval_flag() -> None:
    gate = Gate(Recorder(result(False, "approval_required", "needs a human")), "a")
    denial = gate.check("refund", {})
    assert denial == ToolDenial("refund", "approval_required", "needs a human", True, "aud")
    assert denial is not None and is_tool_denial(denial.to_dict())
    assert denial.to_dict()["approvalRequired"] is True
    assert "Ask the user" in denial.to_text()


def test_denial_defaults_when_server_gives_no_code() -> None:
    denial = Gate(Recorder(result(False)), "a").check("t", {})
    assert denial is not None
    assert (denial.code, denial.reason, denial.approval_required) == (
        "no_permission",
        "Denied by policy",
        False,
    )


@pytest.mark.parametrize("loose", ["true", 1, {}, None])
def test_only_literal_true_allows(loose: Any) -> None:
    gate = Gate(lambda _a, _r: {"allowed": loose, "auditId": "x"}, "a")
    assert gate.check("t", {}) is not None


def test_authorize_exception_fails_closed() -> None:
    denial = Gate(Recorder(RuntimeError("boom")), "a").check("t", {})
    assert denial is not None and denial.code == "guard_error" and "boom" in denial.reason


def test_missing_agent_id_fails_closed_without_calling_authorize() -> None:
    rec = Recorder(result(True))
    denial = Gate(rec, lambda _ctx: None).check("t", {})
    assert denial is not None and denial.code == "guard_error"
    assert rec.calls == []


def test_agent_id_function_gets_context() -> None:
    rec = Recorder(result(True))
    Gate(rec, lambda ctx: ctx["agent"]).check("t", {}, {"agent": "from-ctx"})
    assert rec.agent_ids == ["from-ctx"]


def test_custom_action_and_resource() -> None:
    rec = Recorder(result(True))
    Gate(rec, "a", action="call", resource=lambda n, a: f"db:{n}:{(a or {}).get('t')}").check(
        "q", {"t": "users"}
    )
    assert (rec.calls[0].action, rec.calls[0].resource) == ("call", "db:q:users")


def test_arguments_are_made_json_safe() -> None:
    class Thing:
        def __str__(self) -> str:
            return "thing!"

    @dataclasses.dataclass
    class Box:
        n: int

    rec = Recorder(result(True))
    Gate(rec, "a").check("t", {"x": Thing(), "b": Box(2), "s": {1, 2}, 3: "int key"})
    sent = rec.calls[0].arguments
    assert sent is not None
    json.dumps(sent)
    assert sent["x"] == "thing!" and sent["b"] == {"n": 2} and sent["3"] == "int key"


def test_approval_retries_once_with_approved_id() -> None:
    rec = Recorder(result(False, "approval_required", "r"), result(True, "approval_consumed"))
    seen: List[ApprovalContext] = []

    def ask(ctx: ApprovalContext) -> str:
        seen.append(ctx)
        return "ap1"

    assert Gate(rec, "a", request_approval=ask).check("refund", {"amount": 9}) is None
    assert rec.calls[1].approval_id == "ap1" and rec.calls[0].approval_id is None
    assert seen[0].tool_name == "refund" and seen[0].audit_id == "aud"
    assert seen[0].arguments == {"amount": 9} and seen[0].agent_id == "a"


def test_approval_none_refuses_and_does_not_retry() -> None:
    rec = Recorder(result(False, "approval_required", "r"))
    denial = Gate(rec, "a", request_approval=lambda _c: None).check("t", {})
    assert denial is not None and denial.approval_required
    assert len(rec.calls) == 1


def test_approval_retry_denied_returns_second_denial() -> None:
    rec = Recorder(result(False, "approval_required", "r"), result(False, "approval_invalid", "bad"))
    denial = Gate(rec, "a", request_approval=lambda _c: "ap1").check("t", {})
    assert denial is not None and denial.code == "approval_invalid"
    assert len(rec.calls) == 2


def test_approval_callback_error_fails_closed() -> None:
    def ask(_c: ApprovalContext) -> str:
        raise TimeoutError("human never answered")

    gate = Gate(Recorder(result(False, "approval_required")), "a", request_approval=ask)
    denial = gate.check("t", {})
    assert denial is not None and denial.code == "guard_error"


def test_on_decision_sees_outcomes_and_errors_are_ignored() -> None:
    seen: List[Any] = []

    def log(name: str, denial: Optional[ToolDenial]) -> None:
        seen.append((name, denial))
        raise RuntimeError("logger broke")

    gate = Gate(Recorder(result(True), result(False, "rate_limited")), "a", on_decision=log)
    assert gate.check("t", {}) is None
    second = gate.check("t", {})
    assert second is not None and second.code == "rate_limited"
    assert [s[1] is None for s in seen] == [True, False]


def test_sync_gate_with_async_authorize_fails_closed() -> None:
    async def authorize(_a: str, _r: AuthorizeRequest) -> AuthorizeResult:
        return result(True)

    denial = Gate(authorize, "a").check("t", {})
    assert denial is not None and denial.code == "guard_error"


async def test_async_gate_accepts_sync_and_async_callbacks() -> None:
    calls: List[Optional[str]] = []

    async def authorize(_a: str, request: AuthorizeRequest) -> AuthorizeResult:
        calls.append(request.approval_id)
        return result(True) if request.approval_id else result(False, "approval_required")

    async def ask(_c: ApprovalContext) -> str:
        return "ap9"

    assert await Gate(authorize, "a", request_approval=ask).acheck("t", {}) is None
    assert calls == [None, "ap9"]
    assert await Gate(lambda _a, _r: result(False, "no_permission"), "a").acheck("t", {}) is not None
    boom = await Gate(Recorder(ValueError("x")), "a").acheck("t", {})
    assert boom is not None and boom.code == "guard_error"


# wrapping


def test_wrap_sync_runs_or_refuses_and_keeps_signature() -> None:
    rec = Recorder(result(True), result(False, "no_permission", "nope"))
    ran: List[Dict[str, Any]] = []

    @guard(Gate(rec, "a"), "refund")
    def refund(order_id: str, amount: float = 1.0) -> str:
        """Refund docs."""
        ran.append({"order_id": order_id, "amount": amount})
        return "done"

    assert refund.__doc__ == "Refund docs."
    assert refund.__name__ == "refund"
    assert refund("o1", amount=5) == "done"
    assert rec.calls[0].arguments == {"order_id": "o1", "amount": 5}
    refused: Any = refund("o2")
    assert is_tool_denial(refused) and refused["code"] == "no_permission"
    assert len(ran) == 1


async def test_wrap_async_function() -> None:
    gate = Gate(Recorder(result(True), result(False, "rate_limited")), "a")

    @guard(gate)
    async def fetch(url: str) -> str:
        return f"got {url}"

    assert await fetch("x") == "got x"
    assert is_tool_denial(await fetch("y"))


def test_context_params_are_not_sent_but_feed_agent_id() -> None:
    rec = Recorder(result(True))
    gate = Gate(rec, lambda ctx: ctx["agent"])

    @gate.tool("t")
    def tool(self_like: str, config: Dict[str, str], **extra: Any) -> str:
        return "ok"

    tool("v", {"agent": "cfg-agent"}, color="red")
    assert rec.agent_ids == ["cfg-agent"]
    assert rec.calls[0].arguments == {"self_like": "v", "color": "red"}


def test_methods_skip_self() -> None:
    rec = Recorder(result(True))
    gate = Gate(rec, "a")

    class Svc:
        @gate.tool("svc")
        def run(self, n: int) -> int:
            return n

    assert Svc().run(4) == 4
    assert rec.calls[0].arguments == {"n": 4}


def _make_x() -> str:
    return "x"


def test_format_denial_is_used() -> None:
    gate = Gate(Recorder(result(False, "no_permission", "nope")), "a")
    wrapped = guard_tool(gate, _make_x, "t", format_denial=lambda d: d.to_text())
    assert wrapped() == "Refused (no_permission): nope. Do not retry."


def test_from_token_uses_bearer_route_and_picks_up_rotated_token() -> None:
    tokens = iter(["ta_one", "ta_two"])
    seen: List[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["authorization"])
        body = json.loads(request.content)
        assert body == {"action": "execute", "resource": "tool:t", "arguments": {"n": 1}}
        return httpx.Response(200, json={"data": {"allowed": True, "auditId": "a"}})

    with respx.mock() as router:
        router.post(f"{BASE}/authorize/token").mock(side_effect=handler)
        client = TheAuthSyncClient(base_url=BASE)
        gate = Gate.from_token(client, lambda: next(tokens))
        assert gate.check("t", {"n": 1}) is None
        assert gate.check("t", {"n": 1}) is None
    assert seen == ["Bearer ta_one", "Bearer ta_two"]


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(401, json={"error": {"code": "INVALID_TOKEN", "message": "bad token"}}),
        httpx.Response(500, json={"error": {"message": "down"}}),
        httpx.Response(200, text="not json"),
        httpx.Response(200, json={"data": {"allowed": "yes", "auditId": "a"}}),
        httpx.Response(200, json={"data": {}}),
    ],
)
def test_http_failures_deny(response: httpx.Response) -> None:
    with respx.mock() as router:
        router.post(f"{BASE}/authorize/token").mock(return_value=response)
        gate = Gate.from_token(TheAuthSyncClient(base_url=BASE), "ta_x")
        assert gate.check("t", {}) is not None


def test_network_error_denies_with_guard_error() -> None:
    with respx.mock() as router:
        router.post(f"{BASE}/authorize/token").mock(side_effect=httpx.ConnectTimeout("slow"))
        denial = Gate.from_token(TheAuthSyncClient(base_url=BASE), "ta_x").check("t", {})
    assert denial is not None and denial.code == "guard_error"


async def test_from_token_with_async_client() -> None:
    with respx.mock() as router:
        router.post(f"{BASE}/authorize/token").mock(
            return_value=httpx.Response(
                403,
                json={"data": {"allowed": False, "code": "rate_limited", "reason": "slow down", "auditId": "a"}},
            )
        )
        async with TheAuthClient(base_url=BASE) as client:
            denial = await Gate.from_token(client, "ta_x").acheck("t", {})
    assert denial is not None and denial.code == "rate_limited"


# approval wait


class FakeApprovals:
    def __init__(self, *statuses: Optional[str]) -> None:
        self.statuses = list(statuses)
        self.gets = 0

    def get(self, approval_id: str) -> Optional[ApprovalState]:
        self.gets += 1
        status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
        if status is None:
            return None
        return ApprovalState(approval_id, status, "execute", "tool:t", "2030-01-01T00:00:00Z")


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def test_wait_returns_id_when_approved_after_polling() -> None:
    clock = Clock()
    approvals = FakeApprovals("pending", "pending", "approved")
    got = wait_for_approval(approvals, "ap1", timeout_s=30, poll_interval_s=2, sleep=clock.sleep, clock=clock)
    assert got == "ap1" and approvals.gets == 3 and clock.now == 4


@pytest.mark.parametrize("status", ["denied", "expired", None])
def test_wait_returns_none_for_non_approved(status: Optional[str]) -> None:
    assert wait_for_approval(FakeApprovals(status), "ap1", sleep=lambda _s: None) is None


def test_wait_times_out() -> None:
    clock = Clock()
    approvals = FakeApprovals("pending")
    assert wait_for_approval(approvals, "ap1", timeout_s=5, poll_interval_s=2, sleep=clock.sleep, clock=clock) is None
    assert clock.now == 5


def test_wait_with_async_client_raises_instead_of_hanging() -> None:
    class AsyncApprovals:
        async def get(self, approval_id: str) -> None:
            return None

    with pytest.raises(TypeError):
        wait_for_approval(AsyncApprovals(), "ap1")


async def test_await_approval() -> None:
    class AsyncApprovals:
        def __init__(self) -> None:
            self.n = 0

        async def get(self, approval_id: str) -> ApprovalState:
            self.n += 1
            status = "approved" if self.n >= 2 else "pending"
            return ApprovalState(approval_id, status, "execute", "tool:t", "x")

    assert await await_approval(AsyncApprovals(), "ap1", poll_interval_s=0.001) == "ap1"

    class Pending:
        async def get(self, approval_id: str) -> ApprovalState:
            return ApprovalState(approval_id, "pending", "execute", "tool:t", "x")

    assert await await_approval(Pending(), "ap1", timeout_s=0.01, poll_interval_s=0.001) is None


def test_gate_with_wait_for_approval_end_to_end() -> None:
    rec = Recorder(result(False, "approval_required"), result(True))
    approvals = FakeApprovals("approved")
    gate = Gate(
        rec,
        "a",
        request_approval=lambda _c: wait_for_approval(approvals, "ap1", sleep=lambda _s: None),
    )
    assert gate.check("t", {}) is None
    denied = Gate(
        Recorder(result(False, "approval_required", "r")),
        "a",
        request_approval=lambda _c: wait_for_approval(FakeApprovals("denied"), "ap1"),
    ).check("t", {})
    assert denied is not None and denied.approval_required


# LangGraph


def tool_call(name: str, args: Dict[str, Any], call_id: str) -> Dict[str, Any]:
    return {"name": name, "args": args, "id": call_id}


def test_guard_node_runs_node_when_all_allowed() -> None:
    gate = Gate(Recorder(result(True)), "a")
    node = guard_node(lambda state: {"messages": ["ran"]}, gate)
    state = {"messages": [{"tool_calls": [tool_call("a", {}, "1"), tool_call("b", {}, "2")]}]}
    assert node(state, None) == {"messages": ["ran"]}


def test_guard_node_refuses_whole_step_and_answers_every_call() -> None:
    gate = Gate(Recorder(result(True), result(False, "approval_required", "needs human")), "a")
    ran: List[int] = []
    node = guard_node(lambda state: ran.append(1), gate)
    state = {"messages": [{"tool_calls": [tool_call("a", {}, "1"), tool_call("b", {}, "2")]}]}
    out = node(state, None)
    assert ran == []
    first, second = out["messages"]
    assert first["tool_call_id"] == "1" and json.loads(first["content"])["code"] == "skipped"
    assert second["tool_call_id"] == "2" and json.loads(second["content"])["approvalRequired"] is True
    assert second["role"] == "tool" and second["name"] == "b"


def test_guard_node_passes_through_without_tool_calls_and_supports_objects_and_config() -> None:
    rec = Recorder(result(True))
    seen: List[Any] = []
    def plain(state: Any, config: Any) -> str:
        seen.append(config)
        return "ok"

    node = guard_node(plain, Gate(rec, lambda c: c["agent"]))
    assert node({"messages": []}, {"agent": "x"}) == "ok"
    assert rec.calls == []

    @dataclasses.dataclass
    class Call:
        name: str
        args: Dict[str, Any]
        id: str

    @dataclasses.dataclass
    class Msg:
        tool_calls: List[Call]

    @dataclasses.dataclass
    class State:
        messages: List[Msg]

    assert node(State([Msg([Call("t", {"n": 1}, "c")])]), {"agent": "cfg"}) == "ok"
    assert rec.agent_ids == ["cfg"] and rec.calls[0].arguments == {"n": 1}


def test_guard_node_wraps_runnable_through_invoke() -> None:
    class Runnable:
        def invoke(self, state: Any, config: Any = None) -> str:
            return "invoked"

    node = guard_node(Runnable(), Gate(Recorder(result(True)), "a"))
    state = {"messages": [{"tool_calls": [tool_call("t", {}, "1")]}]}
    assert node(state, None) == "invoked"


async def test_aguard_node_with_runnable_and_async_function() -> None:
    class Runnable:
        async def ainvoke(self, state: Any, config: Any = None) -> str:
            return "ainvoked"

        def invoke(self, state: Any, config: Any = None) -> str:
            return "sync"

    state = {"messages": [{"tool_calls": [tool_call("t", {}, "1")]}]}
    allow = Gate(Recorder(result(True)), "a")
    assert await aguard_node(Runnable(), allow)(state, None) == "ainvoked"

    async def anode(state: Any) -> str:
        return "async fn"

    assert await guard_node(anode, allow)(state, None) == "async fn"
    deny = Gate(Recorder(result(False, "no_permission", "no")), "a")
    out = await aguard_node(Runnable(), deny)(state, None)
    assert out["messages"][0]["tool_call_id"] == "1"


# CrewAI


def test_guard_crewai_tool_with_func_field() -> None:
    class Tool:
        name = "refund"

        def __init__(self) -> None:
            self.func = lambda order_id, amount: f"ok {order_id}"

    gate = Gate(Recorder(result(True), result(False, "no_permission", "nope")), "a")
    tool = guard_crewai_tool(Tool(), gate)
    assert tool.func("o", 1) == "ok o"
    assert tool.func("o", 2) == "Refused (no_permission): nope. Do not retry."


def test_guard_crewai_tool_with_run_method_and_slots_free_pydantic_like_class() -> None:
    class BaseTool:
        name = "web"

        def __setattr__(self, key: str, value: Any) -> None:
            raise ValueError("frozen like a pydantic model")

        def _run(self, query: str) -> str:
            return f"searched {query}"

    gate = Gate(Recorder(result(True), result(False, "rate_limited", "slow")), "a")
    tool = guard_crewai_tool(BaseTool(), gate)
    assert tool._run(query="x") == "searched x"
    assert tool._run(query="y").startswith("Refused (rate_limited)")


def test_guard_crewai_tool_rejects_non_tools() -> None:
    with pytest.raises(TypeError):
        guard_crewai_tool(object(), Gate(Recorder(result(True)), "a"))


# OpenAI Agents SDK


@dataclasses.dataclass
class FakeFunctionTool:
    name: str
    description: str
    on_invoke_tool: Any


def make_tool(name: str = "lookup") -> FakeFunctionTool:
    async def invoke(ctx: Any, input_json: str) -> str:
        return f"ran {json.loads(input_json)['id']}"

    return FakeFunctionTool(name, "desc", invoke)


async def test_guard_function_tool_allows_and_leaves_original_untouched() -> None:
    original = make_tool()
    gate = Gate(Recorder(result(True)), "a")
    guarded = guard_function_tool(original, gate)
    assert guarded is not original and guarded.description == "desc"
    assert await guarded.on_invoke_tool(None, '{"id": "i1"}') == "ran i1"
    assert await original.on_invoke_tool(None, '{"id": "i2"}') == "ran i2"


async def test_guard_function_tool_refuses_with_json_and_checks_arguments() -> None:
    rec = Recorder(result(False, "approval_required", "needs human"))
    guarded = guard_function_tool(make_tool(), Gate(rec, lambda ctx: ctx))
    out = json.loads(await guarded.on_invoke_tool("agent-from-ctx", '{"id": "i1"}'))
    assert out["code"] == "approval_required" and out["toolName"] == "lookup"
    assert rec.calls[0].arguments == {"id": "i1"} and rec.agent_ids == ["agent-from-ctx"]


@pytest.mark.parametrize("bad", ["{nope", "null", "[1]"])
async def test_guard_function_tool_bad_input_never_runs_the_tool(bad: str) -> None:
    rec = Recorder(result(True))
    ran: List[int] = []

    async def invoke(ctx: Any, input_json: str) -> str:
        ran.append(1)
        return "ran"

    guarded = guard_function_tool(FakeFunctionTool("t", "d", invoke), Gate(rec, "a"))
    out = await guarded.on_invoke_tool(None, bad)
    if bad == "{nope":
        assert json.loads(out)["code"] == "guard_error" and rec.calls == []
    else:
        assert rec.calls[0].arguments == {"input": json.loads(bad)}


def test_guard_function_tool_rejects_other_objects_and_lists() -> None:
    gate = Gate(Recorder(result(True)), "a")
    with pytest.raises(TypeError):
        guard_function_tool(object(), gate)
    tools = guard_function_tools([make_tool("a"), make_tool("b")], gate)
    assert [t.name for t in tools] == ["a", "b"]


# import hygiene


def test_importing_integrations_imports_no_framework() -> None:
    code = (
        "import sys\n"
        "import theauth.integrations\n"
        "bad = [m for m in ('langgraph', 'langchain', 'langchain_core', 'crewai', 'agents', 'openai')"
        " if m in sys.modules]\n"
        "assert not bad, bad\n"
    )
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
