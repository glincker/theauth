"""Parity tests: decision codes, explain, approvals, introspection and the route contract.

These run against a real local HTTP server (stdlib), so the wire format is what the
client actually sends: JSON bodies, form bodies, Basic auth and the `{ data }` envelope.
"""

from __future__ import annotations

import base64
import json
import re
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import parse_qs

import pytest

from theauth import (
    AuthenticationError,
    ConsumeApprovalInput,
    DECISION_CODES,
    ExplainRequest,
    IntrospectInput,
    OpenApprovalInput,
    PermissionError,
    TheAuthClient,
    TheAuthError,
    TheAuthSyncClient,
    is_allowed_code,
)
from theauth.types import AuthorizeRequest

OPENAPI = Path(__file__).resolve().parents[2] / "openapi.json"

Reply = Tuple[int, Any]


@dataclass
class Call:
    method: str
    path: str
    headers: Dict[str, str]
    body: str


@dataclass
class FakeServer:
    url: str
    routes: Dict[str, Reply] = field(default_factory=dict)
    calls: List[Call] = field(default_factory=list)

    def last(self) -> Call:
        return self.calls[-1]

    def json_body(self) -> Any:
        return json.loads(self.last().body)


@pytest.fixture
def server() -> Iterator[FakeServer]:
    fake = FakeServer(url="")

    class Handler(BaseHTTPRequestHandler):
        def _serve(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode() if length else ""
            path = self.path.split("?")[0]
            fake.calls.append(
                Call(self.command, path, {k.lower(): v for k, v in self.headers.items()}, body)
            )
            status, payload = fake.routes.get(
                f"{self.command} {path}",
                (404, {"error": {"code": "NOT_FOUND", "message": "no route"}}),
            )
            raw = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        do_GET = do_POST = do_PATCH = do_DELETE = _serve  # noqa: N815

        def log_message(self, *_: Any) -> None:
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    fake.url = f"http://127.0.0.1:{httpd.server_address[1]}"
    thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield fake
    finally:
        httpd.shutdown()
        httpd.server_close()


def data(value: Any) -> Dict[str, Any]:
    return {"data": value}


def sync_client(server: FakeServer, token: Optional[str] = "ta_test") -> TheAuthSyncClient:
    return TheAuthSyncClient(base_url=server.url, token=token)


EXPLAIN_BODY: Dict[str, Any] = {
    "decision": "escalate",
    "allowed": False,
    "code": "approval_required",
    "reason": "approval needed",
    "agent": {"id": "a2", "name": "worker", "ownerId": "u1", "status": "active", "expiresAt": None},
    "delegation": {
        "rootOwnerId": "u1",
        "path": ["a1", "a2"],
        "links": [
            {
                "delegationId": "d1",
                "fromAgent": "a1",
                "toAgent": "a2",
                "permissions": [{"resource": "db:*", "actions": ["write"]}],
                "depth": 1,
                "maxDepth": 3,
                "expiresAt": "2030-01-01T00:00:00.000Z",
                "createdAt": "2029-01-01T00:00:00.000Z",
            }
        ],
        "inbound": [],
    },
    "matchedGrant": {
        "source": "delegation",
        "index": 0,
        "permission": {"resource": "db:*", "actions": ["write"]},
        "resourceMatch": "wildcard:prefix",
        "actionMatch": "exact",
    },
    "constraints": [{"constraint": "requireApproval", "outcome": "approval", "detail": "held"}],
    "attempts": [
        {"source": "delegation", "rulesChecked": 1, "outcome": "escalate", "code": "approval_required"}
    ],
    "hook": {"configured": False, "evaluated": False},
    "nearMisses": [
        {
            "source": "own",
            "grant": {"resource": "db:orders", "actions": ["read"]},
            "mismatch": ["action"],
            "hint": "action read does not cover write",
            "score": 0.6,
        }
    ],
    "trace": [{"stage": "constraint", "outcome": "approval", "detail": "held"}],
    "evaluatedAt": "2029-06-01T00:00:00.000Z",
}


class TestAuthorizeDecisions:
    def test_result_carries_code_and_body_has_agent_id_and_approval_id(
        self, server: FakeServer
    ) -> None:
        server.routes["POST /authorize"] = (
            200,
            data({"allowed": True, "auditId": "aud_1", "code": "approval_consumed"}),
        )
        with sync_client(server) as client:
            result = client.agents.authorize(
                "agent-1",
                AuthorizeRequest(action="write", resource="db:orders", approval_id="apr_9"),
            )
        assert result.allowed is True
        assert result.code == "approval_consumed"
        assert is_allowed_code(result.code)
        body = server.json_body()
        assert body["agentId"] == "agent-1"
        assert body["approvalId"] == "apr_9"
        assert body["action"] == "write"

    def test_denial_is_a_result_not_an_exception(self, server: FakeServer) -> None:
        server.routes["POST /authorize"] = (
            403,
            data(
                {
                    "allowed": False,
                    "auditId": "aud_2",
                    "code": "approval_required",
                    "reason": "needs a human",
                }
            ),
        )
        with sync_client(server) as client:
            result = client.agents.authorize(
                "agent-1", AuthorizeRequest(action="write", resource="db:orders")
            )
        assert result.allowed is False
        assert result.code == "approval_required"
        assert result.reason == "needs a human"
        assert not is_allowed_code(result.code)

    def test_scope_refusal_is_still_an_exception(self, server: FakeServer) -> None:
        server.routes["POST /authorize"] = (
            403,
            {"error": {"code": "FORBIDDEN", "message": "not your agent"}},
        )
        with sync_client(server) as client:
            with pytest.raises(PermissionError) as info:
                client.agents.authorize("agent-1", AuthorizeRequest(action="r", resource="x"))
        assert info.value.code == "FORBIDDEN"

    def test_authorize_by_token_401_is_a_result(self, server: FakeServer) -> None:
        server.routes["POST /authorize/token"] = (
            401,
            data({"allowed": False, "auditId": "aud_3", "code": "invalid_token"}),
        )
        with sync_client(server, token=None) as client:
            result = client.auth.authorize_by_token(
                "ta_bad", AuthorizeRequest(action="read", resource="x")
            )
        assert result.allowed is False
        assert result.code == "invalid_token"
        assert server.last().headers["authorization"] == "Bearer ta_bad"

    @pytest.mark.asyncio
    async def test_async_denial_and_allowed(self, server: FakeServer) -> None:
        server.routes["POST /authorize"] = (
            403,
            data({"allowed": False, "auditId": "aud_4", "code": "rate_limited"}),
        )
        async with TheAuthClient(base_url=server.url, token="ta_test") as client:
            denied = await client.authorize("agent-1", AuthorizeRequest(action="r", resource="x"))
            server.routes["POST /authorize"] = (
                200,
                data({"allowed": True, "auditId": "aud_5", "code": "allowed"}),
            )
            allowed = await client.agents.authorize(
                "agent-1", AuthorizeRequest(action="r", resource="x")
            )
        assert denied.code == "rate_limited" and not denied.allowed
        assert allowed.code == "allowed" and allowed.allowed

    def test_decision_codes_list_matches_the_literal(self) -> None:
        from typing import get_args

        from theauth.codes import DecisionCode

        doc = json.loads(OPENAPI.read_text())
        server_codes = doc["components"]["schemas"]["DecisionCode"]["enum"]
        assert len(DECISION_CODES) == len(set(DECISION_CODES))
        assert list(DECISION_CODES) == server_codes
        assert list(get_args(DecisionCode)) == server_codes
        assert "approval_consumed" in DECISION_CODES


class TestEnvelope:
    def test_data_envelope_is_removed_for_resources(self, server: FakeServer) -> None:
        agent = {
            "id": "a1",
            "ownerId": "u1",
            "name": "bot",
            "type": "autonomous",
            "token": "",
            "permissions": [],
            "status": "active",
            "expiresAt": None,
            "createdAt": "t",
            "updatedAt": "t",
        }
        server.routes["GET /agents/a1"] = (200, data(agent))
        with sync_client(server) as client:
            got = client.agents.get("a1")
        assert got is not None and got.id == "a1"

    def test_generic_request_keeps_the_raw_body(self, server: FakeServer) -> None:
        server.routes["GET /custom"] = (200, data({"x": 1}))
        with sync_client(server) as client:
            assert client.request("GET", "/custom") == {"data": {"x": 1}}


class TestExplainAndChains:
    def test_explain_decodes_chain_constraints_and_near_misses(self, server: FakeServer) -> None:
        server.routes["POST /explain"] = (200, data(EXPLAIN_BODY))
        with sync_client(server) as client:
            result = client.agents.explain(
                ExplainRequest(agent_id="a2", action="write", resource="db:orders", ip="10.0.0.1")
            )
        assert result.decision == "escalate"
        assert result.code == "approval_required"
        assert result.agent is not None and result.agent.owner_id == "u1"
        assert result.delegation is not None
        assert result.delegation.root_owner_id == "u1"
        assert result.delegation.path == ["a1", "a2"]
        assert result.delegation.links[0].max_depth == 3
        assert result.delegation.links[0].permissions[0].resource == "db:*"
        assert result.matched_grant is not None
        assert result.matched_grant.resource_match == "wildcard:prefix"
        assert result.constraints[0].outcome == "approval"
        assert result.attempts[0].code == "approval_required"
        assert result.near_misses[0].grant_resource == "db:orders"
        assert result.trace[0].stage == "constraint"
        body = server.json_body()
        assert body == {
            "agentId": "a2",
            "action": "write",
            "resource": "db:orders",
            "context": {"ip": "10.0.0.1"},
        }

    @pytest.mark.asyncio
    async def test_async_explain_with_unknown_agent(self, server: FakeServer) -> None:
        body = dict(EXPLAIN_BODY, agent=None, delegation=None, matchedGrant=None)
        body.update(decision="deny", code="agent_not_found", nearMisses=[], constraints=[])
        server.routes["POST /explain"] = (200, data(body))
        async with TheAuthClient(base_url=server.url, token="t") as client:
            result = await client.agents.explain(
                ExplainRequest(agent_id="ghost", action="r", resource="x")
            )
        assert result.agent is None and result.delegation is None
        assert result.matched_grant is None
        assert result.code == "agent_not_found"

    def test_delegation_chain_has_root_owner_and_path(self, server: FakeServer) -> None:
        server.routes["GET /delegations/a2"] = (
            200,
            data(
                [
                    {
                        "id": "d1",
                        "fromAgent": "a1",
                        "toAgent": "a2",
                        "permissions": [],
                        "expiresAt": "x",
                        "depth": 1,
                        "createdAt": "y",
                        "rootOwnerId": "u1",
                        "path": ["a1", "a2"],
                    }
                ]
            ),
        )
        with sync_client(server) as client:
            chains = client.delegation.list_chains("a2")
        assert chains[0].root_owner_id == "u1"
        assert chains[0].path == ["a1", "a2"]

    def test_audit_entry_has_code_and_event(self, server: FakeServer) -> None:
        server.routes["GET /audit"] = (
            200,
            data(
                [
                    {
                        "id": "e1",
                        "agentId": "a",
                        "userId": "u",
                        "action": "write",
                        "resource": "r",
                        "parameters": {},
                        "result": "escalated",
                        "durationMs": 3,
                        "timestamp": "t",
                        "code": "approval_required",
                        "event": "authorize",
                    }
                ]
            ),
        )
        with sync_client(server) as client:
            entries = client.audit.query()
        assert entries[0].result == "escalated"
        assert entries[0].code == "approval_required"
        assert entries[0].event == "authorize"


class TestApprovals:
    def test_full_flow(self, server: FakeServer) -> None:
        server.routes.update(
            {
                "POST /approvals": (
                    201,
                    data(
                        {
                            "id": "apr_1",
                            "status": "pending",
                            "action": "admin:rotate",
                            "resource": "agent:a1",
                            "expiresAt": "t",
                        }
                    ),
                ),
                "GET /approvals": (
                    200,
                    data(
                        [
                            {
                                "id": "apr_1",
                                "action": "admin:rotate",
                                "resource": "agent:a1",
                                "requestedBy": "u1",
                                "createdAt": "c",
                                "expiresAt": "e",
                                "arguments": "{}",
                                "argumentsTruncated": False,
                            }
                        ]
                    ),
                ),
                "GET /approvals/apr_1": (
                    200,
                    data(
                        {
                            "id": "apr_1",
                            "status": "approved",
                            "action": "admin:rotate",
                            "resource": "agent:a1",
                            "expiresAt": "e",
                            "respondedAt": "r",
                        }
                    ),
                ),
                "POST /approvals/apr_1/approve": (
                    200,
                    data({"id": "apr_1", "status": "approved", "respondedAt": "r"}),
                ),
                "POST /approvals/apr_1/deny": (
                    200,
                    data({"id": "apr_1", "status": "denied", "respondedAt": "r"}),
                ),
                "POST /approvals/apr_1/consume": (
                    200,
                    data({"consumed": True, "approvalId": "apr_1"}),
                ),
            }
        )
        with sync_client(server, token="admin_token") as client:
            opened = client.approvals.open(OpenApprovalInput("admin:rotate", "agent:a1"))
            assert opened.id == "apr_1" and opened.status == "pending"
            pending = client.approvals.list_pending(limit=10)
            assert pending[0].requested_by == "u1" and pending[0].arguments_truncated is False
            state = client.approvals.get("apr_1")
            assert state is not None and state.status == "approved" and state.responded_at == "r"
            assert client.approvals.approve("apr_1").status == "approved"
            assert client.approvals.deny("apr_1").status == "denied"
            assert client.approvals.consume("apr_1", ConsumeApprovalInput("admin:rotate", "agent:a1"))
            assert client.approvals.get("missing") is None
        list_call = next(c for c in server.calls if c.method == "GET" and c.path == "/approvals")
        assert list_call.headers["authorization"] == "Bearer admin_token"

    def test_conflict_raises_with_server_code(self, server: FakeServer) -> None:
        server.routes["POST /approvals/apr_1/approve"] = (
            409,
            {"error": {"code": "APPROVAL_NOT_PENDING", "message": "Request is no longer pending"}},
        )
        with sync_client(server) as client:
            with pytest.raises(TheAuthError) as info:
                client.approvals.approve("apr_1")
        assert info.value.code == "APPROVAL_NOT_PENDING"
        assert info.value.status_code == 409

    @pytest.mark.asyncio
    async def test_async_open_and_pending(self, server: FakeServer) -> None:
        server.routes["POST /approvals"] = (
            201,
            data(
                {
                    "id": "apr_2",
                    "status": "pending",
                    "action": "admin:x",
                    "resource": "r",
                    "expiresAt": "t",
                }
            ),
        )
        server.routes["GET /approvals"] = (200, data([]))
        async with TheAuthClient(base_url=server.url, token="t") as client:
            opened = await client.approvals.open(OpenApprovalInput("admin:x", "r", {"k": 1}))
            pending = await client.approvals.list_pending()
        assert opened.id == "apr_2"
        assert pending == []
        assert json.loads(server.calls[0].body)["arguments"] == {"k": 1}


class TestIntrospection:
    def test_form_body_basic_auth_and_claims(self, server: FakeServer) -> None:
        server.routes["POST /mcp/introspect"] = (
            200,
            {
                "active": True,
                "scope": "read write",
                "client_id": "cli",
                "sub": "u1",
                "exp": 1900000000,
                "aud": ["https://api.example.com"],
                "token_type": "DPoP",
                "cnf": {"jkt": "thumb"},
                "agent_id": "a2",
                "act": {"sub": "a2", "act": {"sub": "a1"}},
                "theauth_dlg": {"v": 1, "agt": ["a1", "a2"], "lnk": ["d1"]},
            },
        )
        with sync_client(server, token="ignored_bearer") as client:
            result = client.mcp.introspect(
                IntrospectInput(
                    token="tok",
                    token_type_hint="access_token",
                    client_id="rs 1",
                    client_secret="s3cret",
                )
            )
        assert result.active and result.agent_id == "a2" and result.jkt == "thumb"
        assert result.aud == ["https://api.example.com"]
        assert result.act is not None and result.act.act is not None and result.act.act.sub == "a1"
        assert result.delegation is not None and result.delegation.lnk == ["d1"]
        call = server.last()
        assert call.headers["content-type"].startswith("application/x-www-form-urlencoded")
        assert parse_qs(call.body) == {"token": ["tok"], "token_type_hint": ["access_token"]}
        auth = call.headers["authorization"]
        assert auth.startswith("Basic ")
        assert base64.b64decode(auth[6:]).decode() == "rs%201:s3cret"

    def test_inactive_with_string_audience(self, server: FakeServer) -> None:
        server.routes["POST /mcp/introspect"] = (
            200,
            {
                "active": False,
                "aud": "https://api.example.com",
                "theauth_inactive_reason": "delegation_revoked",
            },
        )
        with sync_client(server) as client:
            result = client.mcp.introspect(IntrospectInput("t", client_id="c", client_secret="s"))
        assert result.active is False
        assert result.inactive_reason == "delegation_revoked"
        assert result.aud == ["https://api.example.com"]

    def test_oauth_error_body_maps_to_typed_error(self, server: FakeServer) -> None:
        server.routes["POST /mcp/introspect"] = (
            401,
            {"error": "invalid_client", "error_description": "Client authentication failed"},
        )
        with sync_client(server) as client:
            with pytest.raises(AuthenticationError) as info:
                client.mcp.introspect(IntrospectInput("t", client_id="c", client_secret="bad"))
        assert info.value.code == "invalid_client"
        assert "authentication failed" in str(info.value).lower()

    @pytest.mark.asyncio
    async def test_async_introspect(self, server: FakeServer) -> None:
        server.routes["POST /mcp/introspect"] = (200, {"active": False})
        async with TheAuthClient(base_url=server.url, token="t") as client:
            result = await client.mcp.introspect(IntrospectInput("t", None, "c", "s"))
        assert result.active is False and result.aud == []


class TestRouteContract:
    """Every route the new calls use must exist in the generated OpenAPI document."""

    def test_routes_exist_in_openapi_json(self, server: FakeServer) -> None:
        doc = json.loads(OPENAPI.read_text())
        ok: Reply = (200, {})
        for key in [
            "POST /authorize",
            "POST /authorize/token",
            "POST /explain",
            "POST /mcp/introspect",
            "POST /approvals",
            "GET /approvals",
            "GET /approvals/x",
            "POST /approvals/x/approve",
            "POST /approvals/x/deny",
            "POST /approvals/x/consume",
            "GET /delegations/x",
        ]:
            server.routes[key] = ok
        with sync_client(server) as client:
            for call in (
                lambda: client.agents.authorize("x", AuthorizeRequest("a", "b")),
                lambda: client.auth.authorize_by_token("ta_x", AuthorizeRequest("a", "b")),
                lambda: client.agents.explain(ExplainRequest("x", "a", "b")),
                lambda: client.mcp.introspect(IntrospectInput("t")),
                lambda: client.approvals.open(OpenApprovalInput("admin:a", "b")),
                lambda: client.approvals.list_pending(),
                lambda: client.approvals.get("x"),
                lambda: client.approvals.approve("x"),
                lambda: client.approvals.deny("x"),
                lambda: client.approvals.consume("x", ConsumeApprovalInput("admin:a", "b")),
                lambda: client.delegation.list_chains("x"),
            ):
                try:
                    call()
                except (KeyError, TypeError):
                    pass  # empty bodies do not decode, only the request matters here
        patterns: List[Tuple[str, "re.Pattern[str]"]] = []
        for path, methods in doc["paths"].items():
            regex = "^" + re.sub(r"\\\{[^}]+\\\}", "[^/]+", re.escape(path)) + "$"
            for method in methods:
                patterns.append((method.upper(), re.compile(regex)))
        assert len(server.calls) == 11
        for call_record in server.calls:
            assert any(
                m == call_record.method and p.match(call_record.path) for m, p in patterns
            ), f"{call_record.method} {call_record.path} is not in openapi.json"
