"""Tests for agent CRUD operations."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from theauth import KavachClient, KavachSyncClient
from theauth.errors import NotFoundError
from theauth.types import (
    Agent,
    AgentFilters,
    AuthorizeRequest,
    CreateAgentInput,
    Permission,
    UpdateAgentInput,
)

from tests.conftest import AGENT_FIXTURE, AUTHORIZE_RESULT_FIXTURE, BASE_URL


class TestAsyncAgentCreate:
    @pytest.mark.asyncio
    async def test_create_returns_agent(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.post(f"{BASE_URL}/agents").mock(
                return_value=httpx.Response(200, json=AGENT_FIXTURE)
            )
            agent = await async_client.agents.create(
                CreateAgentInput(
                    owner_id="user-123",
                    name="github-reader",
                    type="autonomous",
                    permissions=[Permission(resource="mcp:github:*", actions=["read"])],
                )
            )

        assert isinstance(agent, Agent)
        assert agent.id == "agent-abc123"
        assert agent.name == "github-reader"
        assert agent.type == "autonomous"
        assert agent.status == "active"
        assert agent.token == "kv_agent_xyz"
        assert len(agent.permissions) == 1
        assert agent.permissions[0].resource == "mcp:github:*"

    @pytest.mark.asyncio
    async def test_create_sends_correct_body(self, async_client: KavachClient) -> None:
        with respx.mock:
            route = respx.post(f"{BASE_URL}/agents").mock(
                return_value=httpx.Response(200, json=AGENT_FIXTURE)
            )
            await async_client.agents.create(
                CreateAgentInput(
                    owner_id="user-123",
                    name="github-reader",
                    type="autonomous",
                    permissions=[Permission(resource="mcp:github:*", actions=["read"])],
                    expires_at="2025-12-31T00:00:00Z",
                )
            )

        body = json.loads(route.calls.last.request.content)
        assert body["ownerId"] == "user-123"
        assert body["name"] == "github-reader"
        assert body["type"] == "autonomous"
        assert body["expiresAt"] == "2025-12-31T00:00:00Z"
        assert body["permissions"][0]["resource"] == "mcp:github:*"

    @pytest.mark.asyncio
    async def test_create_sends_authorization_header(self, async_client: KavachClient) -> None:
        with respx.mock:
            route = respx.post(f"{BASE_URL}/agents").mock(
                return_value=httpx.Response(200, json=AGENT_FIXTURE)
            )
            await async_client.agents.create(
                CreateAgentInput(
                    owner_id="user-123",
                    name="test",
                    type="service",
                    permissions=[],
                )
            )

        request = route.calls.last.request
        assert request.headers["Authorization"] == "Bearer kv_test_token"


class TestAsyncAgentList:
    @pytest.mark.asyncio
    async def test_list_returns_agents(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/agents").mock(
                return_value=httpx.Response(200, json=[AGENT_FIXTURE])
            )
            agents = await async_client.agents.list()

        assert len(agents) == 1
        assert agents[0].id == "agent-abc123"

    @pytest.mark.asyncio
    async def test_list_empty(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/agents").mock(
                return_value=httpx.Response(200, json=[])
            )
            agents = await async_client.agents.list()

        assert agents == []

    @pytest.mark.asyncio
    async def test_list_with_filters(self, async_client: KavachClient) -> None:
        with respx.mock:
            route = respx.get(f"{BASE_URL}/agents").mock(
                return_value=httpx.Response(200, json=[AGENT_FIXTURE])
            )
            await async_client.agents.list(
                AgentFilters(user_id="user-123", status="active", type="autonomous")
            )

        params = dict(route.calls.last.request.url.params)
        assert params["userId"] == "user-123"
        assert params["status"] == "active"
        assert params["type"] == "autonomous"

    @pytest.mark.asyncio
    async def test_list_no_filters_no_params(self, async_client: KavachClient) -> None:
        with respx.mock:
            route = respx.get(f"{BASE_URL}/agents").mock(
                return_value=httpx.Response(200, json=[])
            )
            await async_client.agents.list()

        assert not route.calls.last.request.url.params


class TestAsyncAgentGet:
    @pytest.mark.asyncio
    async def test_get_returns_agent(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/agents/agent-abc123").mock(
                return_value=httpx.Response(200, json=AGENT_FIXTURE)
            )
            agent = await async_client.agents.get("agent-abc123")

        assert agent is not None
        assert agent.id == "agent-abc123"

    @pytest.mark.asyncio
    async def test_get_returns_none_on_404(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/agents/missing").mock(
                return_value=httpx.Response(
                    404,
                    json={"error": {"code": "NOT_FOUND", "message": "Not found"}},
                )
            )
            agent = await async_client.agents.get("missing")

        assert agent is None


class TestAsyncAgentUpdate:
    @pytest.mark.asyncio
    async def test_update_returns_updated_agent(self, async_client: KavachClient) -> None:
        updated = {**AGENT_FIXTURE, "name": "updated-name"}
        with respx.mock:
            respx.patch(f"{BASE_URL}/agents/agent-abc123").mock(
                return_value=httpx.Response(200, json=updated)
            )
            agent = await async_client.agents.update(
                "agent-abc123",
                UpdateAgentInput(name="updated-name"),
            )

        assert agent.name == "updated-name"

    @pytest.mark.asyncio
    async def test_update_sends_only_provided_fields(self, async_client: KavachClient) -> None:
        with respx.mock:
            route = respx.patch(f"{BASE_URL}/agents/agent-abc123").mock(
                return_value=httpx.Response(200, json=AGENT_FIXTURE)
            )
            await async_client.agents.update(
                "agent-abc123",
                UpdateAgentInput(name="new-name"),
            )

        body = json.loads(route.calls.last.request.content)
        assert "name" in body
        assert "permissions" not in body


class TestAsyncAgentRevoke:
    @pytest.mark.asyncio
    async def test_revoke_returns_none(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.delete(f"{BASE_URL}/agents/agent-abc123").mock(
                return_value=httpx.Response(204)
            )
            result = await async_client.agents.revoke("agent-abc123")

        assert result is None

    @pytest.mark.asyncio
    async def test_revoke_raises_not_found(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.delete(f"{BASE_URL}/agents/missing").mock(
                return_value=httpx.Response(
                    404,
                    json={"error": {"code": "NOT_FOUND", "message": "Agent not found"}},
                )
            )
            with pytest.raises(NotFoundError):
                await async_client.agents.revoke("missing")


class TestAsyncAgentRotate:
    @pytest.mark.asyncio
    async def test_rotate_returns_new_token(self, async_client: KavachClient) -> None:
        rotated = {**AGENT_FIXTURE, "token": "kv_new_token"}
        with respx.mock:
            respx.post(f"{BASE_URL}/agents/agent-abc123/rotate").mock(
                return_value=httpx.Response(200, json=rotated)
            )
            agent = await async_client.agents.rotate("agent-abc123")

        assert agent.token == "kv_new_token"


class TestAsyncAgentAuthorize:
    @pytest.mark.asyncio
    async def test_authorize_allowed(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.post(f"{BASE_URL}/agents/agent-abc123/authorize").mock(
                return_value=httpx.Response(200, json=AUTHORIZE_RESULT_FIXTURE)
            )
            result = await async_client.agents.authorize(
                "agent-abc123",
                AuthorizeRequest(action="read", resource="mcp:github:repos"),
            )

        assert result.allowed is True
        assert result.audit_id == "aud-abc123"

    @pytest.mark.asyncio
    async def test_authorize_denied(self, async_client: KavachClient) -> None:
        denied = {"allowed": False, "auditId": "aud-denied", "reason": "Permission not granted"}
        with respx.mock:
            respx.post(f"{BASE_URL}/agents/agent-abc123/authorize").mock(
                return_value=httpx.Response(200, json=denied)
            )
            result = await async_client.agents.authorize(
                "agent-abc123",
                AuthorizeRequest(action="write", resource="mcp:github:repos"),
            )

        assert result.allowed is False
        assert result.reason == "Permission not granted"

    @pytest.mark.asyncio
    async def test_authorize_includes_arguments(self, async_client: KavachClient) -> None:
        with respx.mock:
            route = respx.post(f"{BASE_URL}/agents/agent-abc123/authorize").mock(
                return_value=httpx.Response(200, json=AUTHORIZE_RESULT_FIXTURE)
            )
            await async_client.agents.authorize(
                "agent-abc123",
                AuthorizeRequest(
                    action="execute",
                    resource="mcp:deploy",
                    arguments={"env": "production"},
                ),
            )

        body = json.loads(route.calls.last.request.content)
        assert body["arguments"] == {"env": "production"}


class TestSyncAgents:
    """Spot-check the sync agent resource mirrors the async one."""

    def test_create(self, sync_client: KavachSyncClient) -> None:
        with respx.mock:
            respx.post(f"{BASE_URL}/agents").mock(
                return_value=httpx.Response(200, json=AGENT_FIXTURE)
            )
            agent = sync_client.agents.create(
                CreateAgentInput(
                    owner_id="user-123",
                    name="github-reader",
                    type="autonomous",
                    permissions=[Permission(resource="mcp:github:*", actions=["read"])],
                )
            )

        assert agent.id == "agent-abc123"

    def test_list(self, sync_client: KavachSyncClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/agents").mock(
                return_value=httpx.Response(200, json=[AGENT_FIXTURE])
            )
            agents = sync_client.agents.list()

        assert len(agents) == 1

    def test_revoke(self, sync_client: KavachSyncClient) -> None:
        with respx.mock:
            respx.delete(f"{BASE_URL}/agents/agent-abc123").mock(
                return_value=httpx.Response(204)
            )
            result = sync_client.agents.revoke("agent-abc123")

        assert result is None

    def test_rotate(self, sync_client: KavachSyncClient) -> None:
        rotated = {**AGENT_FIXTURE, "token": "kv_new_token"}
        with respx.mock:
            respx.post(f"{BASE_URL}/agents/agent-abc123/rotate").mock(
                return_value=httpx.Response(200, json=rotated)
            )
            agent = sync_client.agents.rotate("agent-abc123")

        assert agent.token == "kv_new_token"

    def test_get_returns_none_on_404(self, sync_client: KavachSyncClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/agents/missing").mock(
                return_value=httpx.Response(
                    404,
                    json={"error": {"code": "NOT_FOUND", "message": "Not found"}},
                )
            )
            agent = sync_client.agents.get("missing")

        assert agent is None
