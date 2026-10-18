"""Tests for the mcp resource, the generic request() method and error mapping."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from theauth import (
    PermissionError,
    RateLimitError,
    TheAuthClient,
    TheAuthSyncClient,
    ValidationError,
)
from theauth.types import McpServer, RegisterMcpServerInput

from tests.conftest import BASE_URL, MCP_SERVER_FIXTURE


class TestMcpAsync:
    @pytest.mark.asyncio
    async def test_register(self, async_client: TheAuthClient) -> None:
        with respx.mock:
            route = respx.post(f"{BASE_URL}/mcp/servers").mock(
                return_value=httpx.Response(201, json=MCP_SERVER_FIXTURE)
            )
            server = await async_client.mcp.register(
                RegisterMcpServerInput(
                    name="github-mcp",
                    endpoint="https://mcp.github.com",
                    tools=["read_file"],
                    rate_limit_rpm=60,
                )
            )
        assert isinstance(server, McpServer)
        assert server.id == "mcp-abc123"
        body = json.loads(route.calls[0].request.content)
        assert body["rateLimit"] == {"rpm": 60}
        assert body["authRequired"] is True

    @pytest.mark.asyncio
    async def test_list(self, async_client: TheAuthClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/mcp/servers").mock(
                return_value=httpx.Response(200, json=[MCP_SERVER_FIXTURE])
            )
            servers = await async_client.mcp.list()
        assert [s.name for s in servers] == ["github-mcp"]

    @pytest.mark.asyncio
    async def test_get_and_not_found(self, async_client: TheAuthClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/mcp/servers/mcp-abc123").mock(
                return_value=httpx.Response(200, json=MCP_SERVER_FIXTURE)
            )
            respx.get(f"{BASE_URL}/mcp/servers/missing").mock(
                return_value=httpx.Response(404, json={"error": {"code": "NOT_FOUND", "message": "x"}})
            )
            assert (await async_client.mcp.get("mcp-abc123")) is not None
            assert (await async_client.mcp.get("missing")) is None


class TestMcpSync:
    def test_register_list_get(self, sync_client: TheAuthSyncClient) -> None:
        with respx.mock:
            respx.post(f"{BASE_URL}/mcp/servers").mock(
                return_value=httpx.Response(201, json=MCP_SERVER_FIXTURE)
            )
            respx.get(f"{BASE_URL}/mcp/servers").mock(
                return_value=httpx.Response(200, json=[MCP_SERVER_FIXTURE])
            )
            respx.get(f"{BASE_URL}/mcp/servers/nope").mock(return_value=httpx.Response(404, json={}))
            s = sync_client.mcp.register(
                RegisterMcpServerInput(name="n", endpoint="https://e", tools=[])
            )
            assert s.id == "mcp-abc123"
            assert len(sync_client.mcp.list()) == 1
            assert sync_client.mcp.get("nope") is None


class TestRequest:
    @pytest.mark.asyncio
    async def test_async_request_sends_params_and_json(self, async_client: TheAuthClient) -> None:
        with respx.mock:
            route = respx.post(f"{BASE_URL}/auth/team/invite").mock(
                return_value=httpx.Response(200, json={"ok": True})
            )
            out = await async_client.request(
                "post",
                "/auth/team/invite",
                params={"dry": True, "skip": None, "n": 2},
                json={"email": "a@b.c"},
            )
        assert out == {"ok": True}
        req = route.calls[0].request
        assert req.url.params["dry"] == "true"
        assert req.url.params["n"] == "2"
        assert "skip" not in req.url.params
        assert json.loads(req.content) == {"email": "a@b.c"}
        assert req.headers["authorization"] == "Bearer ta_test_token"

    def test_sync_request_validation_error(self, sync_client: TheAuthSyncClient) -> None:
        issues = [{"where": "body", "path": "email", "message": "Invalid email"}]
        with respx.mock:
            respx.post(f"{BASE_URL}/auth/team/invite").mock(
                return_value=httpx.Response(
                    400,
                    json={
                        "error": {
                            "code": "INVALID_INPUT",
                            "message": "Request did not match the endpoint schema",
                            "issues": issues,
                        }
                    },
                )
            )
            with pytest.raises(ValidationError) as exc:
                sync_client.request("POST", "/auth/team/invite", json={"email": "x"})
        assert exc.value.issues == issues
        assert exc.value.code == "INVALID_INPUT"
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_invalid_json_without_issues_is_validation_error(
        self, async_client: TheAuthClient
    ) -> None:
        with respx.mock:
            respx.post(f"{BASE_URL}/x").mock(
                return_value=httpx.Response(
                    400, json={"error": {"code": "INVALID_INPUT", "message": "bad"}}
                )
            )
            with pytest.raises(ValidationError):
                await async_client.request("POST", "/x")

    @pytest.mark.asyncio
    async def test_other_400_stays_generic(self, async_client: TheAuthClient) -> None:
        from theauth import TheAuthError

        with respx.mock:
            respx.post(f"{BASE_URL}/x").mock(
                return_value=httpx.Response(400, json={"error": {"code": "INVALID_JSON", "message": "m"}})
            )
            with pytest.raises(TheAuthError) as exc:
                await async_client.request("POST", "/x")
        assert not isinstance(exc.value, ValidationError)
        assert exc.value.code == "INVALID_JSON"

    def test_csrf_rejected_maps_to_permission_error(self, sync_client: TheAuthSyncClient) -> None:
        with respx.mock:
            respx.post(f"{BASE_URL}/x").mock(
                return_value=httpx.Response(
                    403,
                    json={"error": {"code": "CSRF_REJECTED", "message": "Cross-site request rejected"}},
                )
            )
            with pytest.raises(PermissionError) as exc:
                sync_client.request("POST", "/x")
        assert exc.value.code == "CSRF_REJECTED"
        assert exc.value.status_code == 403

    def test_rate_limited_maps_with_retry_after(self, sync_client: TheAuthSyncClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/x").mock(
                return_value=httpx.Response(
                    429,
                    headers={"Retry-After": "7"},
                    json={"error": {"code": "RATE_LIMITED", "message": "slow down"}},
                )
            )
            with pytest.raises(RateLimitError) as exc:
                sync_client.request("GET", "/x")
        assert exc.value.retry_after == 7
        assert exc.value.code == "RATE_LIMITED"
