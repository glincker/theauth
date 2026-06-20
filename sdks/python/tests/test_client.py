"""Tests for client initialization and configuration."""

from __future__ import annotations

import pytest
import respx
import httpx

from theauth import KavachClient, KavachSyncClient
from theauth.agents import AsyncAgentsResource, SyncAgentsResource
from theauth.audit import AsyncAuditResource, SyncAuditResource
from theauth.auth import AsyncAuthResource, SyncAuthResource
from theauth.delegation import AsyncDelegationResource, SyncDelegationResource
from theauth.errors import (
    AuthenticationError,
    KavachError,
    NetworkError,
    NotFoundError,
    PermissionError,
    RateLimitError,
    ServerError,
)

from tests.conftest import AGENT_FIXTURE, BASE_URL


class TestKavachClientInit:
    """Test async client initialization."""

    def test_creates_resource_attributes(self, async_client: KavachClient) -> None:
        assert isinstance(async_client.agents, AsyncAgentsResource)
        assert isinstance(async_client.auth, AsyncAuthResource)
        assert isinstance(async_client.audit, AsyncAuditResource)
        assert isinstance(async_client.delegation, AsyncDelegationResource)

    def test_no_token_client(self) -> None:
        client = KavachClient(base_url=BASE_URL)
        assert client._transport._token is None

    def test_custom_headers(self) -> None:
        client = KavachClient(
            base_url=BASE_URL,
            headers={"X-Tenant": "acme"},
        )
        assert client._transport._extra_headers == {"X-Tenant": "acme"}

    def test_base_url_trailing_slash_stripped(self) -> None:
        client = KavachClient(base_url=f"{BASE_URL}/")
        assert not client._transport._base.endswith("/")

    def test_custom_timeout(self) -> None:
        client = KavachClient(base_url=BASE_URL, timeout=60.0)
        assert client._transport._timeout == 60.0


class TestKavachSyncClientInit:
    """Test sync client initialization."""

    def test_creates_resource_attributes(self, sync_client: KavachSyncClient) -> None:
        assert isinstance(sync_client.agents, SyncAgentsResource)
        assert isinstance(sync_client.auth, SyncAuthResource)
        assert isinstance(sync_client.audit, SyncAuditResource)
        assert isinstance(sync_client.delegation, SyncDelegationResource)


class TestContextManager:
    """Test async/sync context manager usage."""

    @pytest.mark.asyncio
    async def test_async_context_manager(self) -> None:
        async with KavachClient(base_url=BASE_URL, token="kv_test") as client:
            assert client._transport is not None

    def test_sync_context_manager(self) -> None:
        with KavachSyncClient(base_url=BASE_URL, token="kv_test") as client:
            assert client._transport is not None


class TestErrorMapping:
    """Test that HTTP errors map to the correct exception types."""

    @pytest.mark.asyncio
    async def test_401_raises_authentication_error(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/agents").mock(
                return_value=httpx.Response(
                    401,
                    json={"error": {"code": "UNAUTHORIZED", "message": "Token expired"}},
                )
            )
            with pytest.raises(AuthenticationError) as exc_info:
                await async_client.agents.list()

        assert exc_info.value.status_code == 401
        assert exc_info.value.code == "UNAUTHORIZED"

    @pytest.mark.asyncio
    async def test_403_raises_permission_error(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/agents").mock(
                return_value=httpx.Response(
                    403,
                    json={"error": {"code": "FORBIDDEN", "message": "Access denied"}},
                )
            )
            with pytest.raises(PermissionError) as exc_info:
                await async_client.agents.list()

        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_404_raises_not_found_error(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/agents/missing-id").mock(
                return_value=httpx.Response(
                    404,
                    json={"error": {"code": "NOT_FOUND", "message": "Agent not found"}},
                )
            )
            with pytest.raises(NotFoundError):
                await async_client._transport.request("GET", "/agents/missing-id")

    @pytest.mark.asyncio
    async def test_429_raises_rate_limit_error(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/agents").mock(
                return_value=httpx.Response(
                    429,
                    headers={"Retry-After": "60"},
                    json={"error": {"code": "RATE_LIMITED", "message": "Too many requests"}},
                )
            )
            with pytest.raises(RateLimitError) as exc_info:
                await async_client.agents.list()

        assert exc_info.value.retry_after == 60

    @pytest.mark.asyncio
    async def test_500_raises_server_error(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/agents").mock(
                return_value=httpx.Response(
                    500,
                    json={"error": {"code": "INTERNAL_ERROR", "message": "Server error"}},
                )
            )
            with pytest.raises(ServerError):
                await async_client.agents.list()

    @pytest.mark.asyncio
    async def test_network_error_raises_network_error(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/agents").mock(side_effect=httpx.ConnectError("refused"))
            with pytest.raises(NetworkError):
                await async_client.agents.list()

    @pytest.mark.asyncio
    async def test_error_without_json_body(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/agents").mock(
                return_value=httpx.Response(503, text="Service Unavailable")
            )
            with pytest.raises(KavachError) as exc_info:
                await async_client.agents.list()

        assert exc_info.value.status_code == 503

    def test_sync_401_raises_authentication_error(self, sync_client: KavachSyncClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/agents").mock(
                return_value=httpx.Response(
                    401,
                    json={"error": {"code": "UNAUTHORIZED", "message": "Bad token"}},
                )
            )
            with pytest.raises(AuthenticationError):
                sync_client.agents.list()

    def test_sync_429_raises_rate_limit_error(self, sync_client: KavachSyncClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/agents").mock(
                return_value=httpx.Response(
                    429,
                    headers={"Retry-After": "30"},
                    json={"error": {"code": "RATE_LIMITED", "message": "Slow down"}},
                )
            )
            with pytest.raises(RateLimitError) as exc_info:
                sync_client.agents.list()

        assert exc_info.value.retry_after == 30
