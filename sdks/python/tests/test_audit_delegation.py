"""Tests for audit log queries and delegation chain management."""

from __future__ import annotations

import pytest
import respx
import httpx

from theauth import KavachClient, KavachSyncClient
from theauth.types import (
    AuditEntry,
    AuditFilters,
    DelegateInput,
    DelegationChain,
    ExportOptions,
    Permission,
    PaginatedAuditLogs,
)

from tests.conftest import (
    AUDIT_ENTRY_FIXTURE,
    BASE_URL,
    DELEGATION_FIXTURE,
)


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


class TestAsyncAuditQuery:
    @pytest.mark.asyncio
    async def test_query_returns_list(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/audit").mock(
                return_value=httpx.Response(200, json=[AUDIT_ENTRY_FIXTURE])
            )
            entries = await async_client.audit.query()

        assert len(entries) == 1
        assert isinstance(entries[0], AuditEntry)
        assert entries[0].id == "aud-abc123"
        assert entries[0].result == "allowed"

    @pytest.mark.asyncio
    async def test_query_with_filters(self, async_client: KavachClient) -> None:
        with respx.mock:
            route = respx.get(f"{BASE_URL}/audit").mock(
                return_value=httpx.Response(200, json=[AUDIT_ENTRY_FIXTURE])
            )
            await async_client.audit.query(
                AuditFilters(
                    agent_id="agent-abc123",
                    result="allowed",
                    limit=50,
                    offset=0,
                )
            )

        params = dict(route.calls.last.request.url.params)
        assert params["agentId"] == "agent-abc123"
        assert params["result"] == "allowed"
        assert params["limit"] == "50"
        assert params["offset"] == "0"

    @pytest.mark.asyncio
    async def test_query_handles_paginated_response(self, async_client: KavachClient) -> None:
        paginated = {
            "entries": [AUDIT_ENTRY_FIXTURE],
            "total": 100,
        }
        with respx.mock:
            respx.get(f"{BASE_URL}/audit").mock(
                return_value=httpx.Response(200, json=paginated)
            )
            entries = await async_client.audit.query()

        assert len(entries) == 1

    @pytest.mark.asyncio
    async def test_query_paginated_returns_total(self, async_client: KavachClient) -> None:
        paginated = {
            "entries": [AUDIT_ENTRY_FIXTURE],
            "total": 100,
        }
        with respx.mock:
            respx.get(f"{BASE_URL}/audit").mock(
                return_value=httpx.Response(200, json=paginated)
            )
            result = await async_client.audit.query_paginated()

        assert isinstance(result, PaginatedAuditLogs)
        assert result.total == 100
        assert len(result.entries) == 1

    @pytest.mark.asyncio
    async def test_query_filters_actions(self, async_client: KavachClient) -> None:
        with respx.mock:
            route = respx.get(f"{BASE_URL}/audit").mock(
                return_value=httpx.Response(200, json=[])
            )
            await async_client.audit.query(
                AuditFilters(actions=["read", "write"])
            )

        params = dict(route.calls.last.request.url.params)
        assert params["actions"] == "read,write"


class TestAsyncAuditExport:
    @pytest.mark.asyncio
    async def test_export_json(self, async_client: KavachClient) -> None:
        export_data = '[{"id": "aud-abc123"}]'
        with respx.mock:
            route = respx.get(f"{BASE_URL}/audit/export").mock(
                return_value=httpx.Response(200, text=export_data)
            )
            result = await async_client.audit.export(ExportOptions(format="json"))

        assert result == export_data
        params = dict(route.calls.last.request.url.params)
        assert params["format"] == "json"

    @pytest.mark.asyncio
    async def test_export_csv(self, async_client: KavachClient) -> None:
        csv_data = "id,action\naud-abc123,read"
        with respx.mock:
            route = respx.get(f"{BASE_URL}/audit/export").mock(
                return_value=httpx.Response(200, text=csv_data)
            )
            result = await async_client.audit.export(ExportOptions(format="csv"))

        assert "read" in result
        params = dict(route.calls.last.request.url.params)
        assert params["format"] == "csv"

    @pytest.mark.asyncio
    async def test_export_defaults_to_json(self, async_client: KavachClient) -> None:
        with respx.mock:
            route = respx.get(f"{BASE_URL}/audit/export").mock(
                return_value=httpx.Response(200, text="[]")
            )
            await async_client.audit.export()

        params = dict(route.calls.last.request.url.params)
        assert params["format"] == "json"

    @pytest.mark.asyncio
    async def test_export_with_date_range(self, async_client: KavachClient) -> None:
        with respx.mock:
            route = respx.get(f"{BASE_URL}/audit/export").mock(
                return_value=httpx.Response(200, text="[]")
            )
            await async_client.audit.export(
                ExportOptions(
                    format="json",
                    since="2024-01-01T00:00:00Z",
                    until="2024-12-31T23:59:59Z",
                )
            )

        params = dict(route.calls.last.request.url.params)
        assert params["since"] == "2024-01-01T00:00:00Z"
        assert params["until"] == "2024-12-31T23:59:59Z"


class TestSyncAudit:
    def test_query(self, sync_client: KavachSyncClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/audit").mock(
                return_value=httpx.Response(200, json=[AUDIT_ENTRY_FIXTURE])
            )
            entries = sync_client.audit.query()

        assert len(entries) == 1
        assert entries[0].agent_id == "agent-abc123"

    def test_export(self, sync_client: KavachSyncClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/audit/export").mock(
                return_value=httpx.Response(200, text="[]")
            )
            result = sync_client.audit.export()

        assert result == "[]"


# ---------------------------------------------------------------------------
# Delegation
# ---------------------------------------------------------------------------


class TestAsyncDelegationCreate:
    @pytest.mark.asyncio
    async def test_create_returns_chain(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.post(f"{BASE_URL}/delegations").mock(
                return_value=httpx.Response(200, json=DELEGATION_FIXTURE)
            )
            chain = await async_client.delegation.create(
                DelegateInput(
                    from_agent="agent-abc123",
                    to_agent="agent-def456",
                    permissions=[Permission(resource="mcp:github:*", actions=["read"])],
                    expires_at="2025-01-01T00:00:00Z",
                    max_depth=2,
                )
            )

        assert isinstance(chain, DelegationChain)
        assert chain.id == "del-abc123"
        assert chain.depth == 1

    @pytest.mark.asyncio
    async def test_create_sends_correct_body(self, async_client: KavachClient) -> None:
        with respx.mock:
            route = respx.post(f"{BASE_URL}/delegations").mock(
                return_value=httpx.Response(200, json=DELEGATION_FIXTURE)
            )
            await async_client.delegation.create(
                DelegateInput(
                    from_agent="agent-abc123",
                    to_agent="agent-def456",
                    permissions=[Permission(resource="mcp:github:*", actions=["read"])],
                    expires_at="2025-01-01T00:00:00Z",
                    max_depth=2,
                )
            )

        import json
        body = json.loads(route.calls.last.request.content)
        assert body["fromAgent"] == "agent-abc123"
        assert body["toAgent"] == "agent-def456"
        assert body["maxDepth"] == 2
        assert body["expiresAt"] == "2025-01-01T00:00:00Z"

    @pytest.mark.asyncio
    async def test_create_without_max_depth(self, async_client: KavachClient) -> None:
        with respx.mock:
            route = respx.post(f"{BASE_URL}/delegations").mock(
                return_value=httpx.Response(200, json=DELEGATION_FIXTURE)
            )
            await async_client.delegation.create(
                DelegateInput(
                    from_agent="agent-abc123",
                    to_agent="agent-def456",
                    permissions=[],
                    expires_at="2025-01-01T00:00:00Z",
                )
            )

        import json
        body = json.loads(route.calls.last.request.content)
        assert "maxDepth" not in body


class TestAsyncDelegationListChains:
    @pytest.mark.asyncio
    async def test_list_chains(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/delegations/agent-abc123").mock(
                return_value=httpx.Response(200, json=[DELEGATION_FIXTURE])
            )
            chains = await async_client.delegation.list_chains("agent-abc123")

        assert len(chains) == 1
        assert chains[0].from_agent == "agent-abc123"
        assert chains[0].to_agent == "agent-def456"

    @pytest.mark.asyncio
    async def test_list_chains_empty(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/delegations/agent-abc123").mock(
                return_value=httpx.Response(200, json=[])
            )
            chains = await async_client.delegation.list_chains("agent-abc123")

        assert chains == []


class TestAsyncDelegationRevoke:
    @pytest.mark.asyncio
    async def test_revoke_delegation(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.delete(f"{BASE_URL}/delegations/del-abc123").mock(
                return_value=httpx.Response(204)
            )
            result = await async_client.delegation.revoke("del-abc123")

        assert result is None


class TestAsyncDelegationEffectivePermissions:
    @pytest.mark.asyncio
    async def test_get_effective_permissions(self, async_client: KavachClient) -> None:
        permissions_data = [
            {"resource": "mcp:github:*", "actions": ["read"]},
            {"resource": "mcp:deploy:staging", "actions": ["execute"]},
        ]
        with respx.mock:
            respx.get(f"{BASE_URL}/delegations/agent-abc123/permissions").mock(
                return_value=httpx.Response(200, json=permissions_data)
            )
            perms = await async_client.delegation.get_effective_permissions("agent-abc123")

        assert len(perms) == 2
        assert isinstance(perms[0], Permission)
        assert perms[0].resource == "mcp:github:*"
        assert perms[1].actions == ["execute"]


class TestSyncDelegation:
    def test_create(self, sync_client: KavachSyncClient) -> None:
        with respx.mock:
            respx.post(f"{BASE_URL}/delegations").mock(
                return_value=httpx.Response(200, json=DELEGATION_FIXTURE)
            )
            chain = sync_client.delegation.create(
                DelegateInput(
                    from_agent="agent-abc123",
                    to_agent="agent-def456",
                    permissions=[Permission(resource="mcp:github:*", actions=["read"])],
                    expires_at="2025-01-01T00:00:00Z",
                )
            )

        assert chain.id == "del-abc123"

    def test_list_chains(self, sync_client: KavachSyncClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/delegations/agent-abc123").mock(
                return_value=httpx.Response(200, json=[DELEGATION_FIXTURE])
            )
            chains = sync_client.delegation.list_chains("agent-abc123")

        assert len(chains) == 1

    def test_revoke(self, sync_client: KavachSyncClient) -> None:
        with respx.mock:
            respx.delete(f"{BASE_URL}/delegations/del-abc123").mock(
                return_value=httpx.Response(204)
            )
            result = sync_client.delegation.revoke("del-abc123")

        assert result is None
