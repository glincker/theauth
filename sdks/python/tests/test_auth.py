"""Tests for authentication operations."""

from __future__ import annotations

import pytest
import respx
import httpx

from theauth import KavachClient, KavachSyncClient
from theauth.types import AuthorizeRequest, AuthResponse, Session

from tests.conftest import (
    AUTH_RESPONSE_FIXTURE,
    AUTHORIZE_RESULT_FIXTURE,
    BASE_URL,
    SESSION_FIXTURE,
)


class TestAsyncSignIn:
    @pytest.mark.asyncio
    async def test_sign_in_returns_auth_response(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.post(f"{BASE_URL}/sign-in/email").mock(
                return_value=httpx.Response(200, json=AUTH_RESPONSE_FIXTURE)
            )
            response = await async_client.auth.sign_in(
                email="user@example.com",
                password="secret123",
            )

        assert isinstance(response, AuthResponse)
        assert response.user.email == "user@example.com"
        assert response.session.token == "sess_token_xyz"

    @pytest.mark.asyncio
    async def test_sign_in_sends_correct_body(self, async_client: KavachClient) -> None:
        with respx.mock:
            route = respx.post(f"{BASE_URL}/sign-in/email").mock(
                return_value=httpx.Response(200, json=AUTH_RESPONSE_FIXTURE)
            )
            await async_client.auth.sign_in(
                email="user@example.com",
                password="secret123",
            )

        import json
        body = json.loads(route.calls.last.request.content)
        assert body["email"] == "user@example.com"
        assert body["password"] == "secret123"

    @pytest.mark.asyncio
    async def test_sign_in_does_not_require_auth_header(self, async_client: KavachClient) -> None:
        """Sign-in is a public endpoint — the Authorization header should still be
        sent if a token is set on the client, but a missing token should not block the call."""
        client = KavachClient(base_url=BASE_URL)  # no token
        with respx.mock:
            respx.post(f"{BASE_URL}/sign-in/email").mock(
                return_value=httpx.Response(200, json=AUTH_RESPONSE_FIXTURE)
            )
            response = await client.auth.sign_in("user@example.com", "pw")

        assert response.user.id == "user-123"


class TestAsyncSignUp:
    @pytest.mark.asyncio
    async def test_sign_up_returns_auth_response(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.post(f"{BASE_URL}/sign-up/email").mock(
                return_value=httpx.Response(200, json=AUTH_RESPONSE_FIXTURE)
            )
            response = await async_client.auth.sign_up(
                email="new@example.com",
                password="secret123",
                name="New User",
            )

        assert response.user.email == "user@example.com"

    @pytest.mark.asyncio
    async def test_sign_up_includes_name(self, async_client: KavachClient) -> None:
        with respx.mock:
            route = respx.post(f"{BASE_URL}/sign-up/email").mock(
                return_value=httpx.Response(200, json=AUTH_RESPONSE_FIXTURE)
            )
            await async_client.auth.sign_up(
                email="new@example.com",
                password="secret123",
                name="New User",
            )

        import json
        body = json.loads(route.calls.last.request.content)
        assert body["name"] == "New User"

    @pytest.mark.asyncio
    async def test_sign_up_without_name(self, async_client: KavachClient) -> None:
        with respx.mock:
            route = respx.post(f"{BASE_URL}/sign-up/email").mock(
                return_value=httpx.Response(200, json=AUTH_RESPONSE_FIXTURE)
            )
            await async_client.auth.sign_up(
                email="new@example.com",
                password="secret123",
            )

        import json
        body = json.loads(route.calls.last.request.content)
        assert "name" not in body


class TestAsyncSignOut:
    @pytest.mark.asyncio
    async def test_sign_out_returns_none(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.post(f"{BASE_URL}/sign-out").mock(
                return_value=httpx.Response(204)
            )
            result = await async_client.auth.sign_out()

        assert result is None

    @pytest.mark.asyncio
    async def test_sign_out_with_explicit_token(self, async_client: KavachClient) -> None:
        with respx.mock:
            route = respx.post(f"{BASE_URL}/sign-out").mock(
                return_value=httpx.Response(204)
            )
            await async_client.auth.sign_out(token="explicit_session_token")

        request = route.calls.last.request
        assert request.headers["Authorization"] == "Bearer explicit_session_token"


class TestAsyncGetSession:
    @pytest.mark.asyncio
    async def test_get_session_returns_session(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/session").mock(
                return_value=httpx.Response(200, json=SESSION_FIXTURE)
            )
            session = await async_client.auth.get_session()

        assert isinstance(session, Session)
        assert session.id == "sess-abc"
        assert session.token == "sess_token_xyz"

    @pytest.mark.asyncio
    async def test_get_session_returns_none_on_401(self, async_client: KavachClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/session").mock(
                return_value=httpx.Response(
                    401,
                    json={"error": {"code": "UNAUTHORIZED", "message": "Token expired"}},
                )
            )
            session = await async_client.auth.get_session()

        assert session is None

    @pytest.mark.asyncio
    async def test_get_session_with_explicit_token(self, async_client: KavachClient) -> None:
        with respx.mock:
            route = respx.get(f"{BASE_URL}/session").mock(
                return_value=httpx.Response(200, json=SESSION_FIXTURE)
            )
            await async_client.auth.get_session(token="override_token")

        request = route.calls.last.request
        assert request.headers["Authorization"] == "Bearer override_token"


class TestAsyncAuthorizeByToken:
    @pytest.mark.asyncio
    async def test_authorize_by_token(self, async_client: KavachClient) -> None:
        with respx.mock:
            route = respx.post(f"{BASE_URL}/authorize").mock(
                return_value=httpx.Response(200, json=AUTHORIZE_RESULT_FIXTURE)
            )
            result = await async_client.auth.authorize_by_token(
                agent_token="kv_agent_direct",
                request=AuthorizeRequest(action="read", resource="mcp:github:*"),
            )

        assert result.allowed is True
        # Token override should be used, not the client-level token
        request = route.calls.last.request
        assert request.headers["Authorization"] == "Bearer kv_agent_direct"


class TestSyncAuth:
    def test_sign_in(self, sync_client: KavachSyncClient) -> None:
        with respx.mock:
            respx.post(f"{BASE_URL}/sign-in/email").mock(
                return_value=httpx.Response(200, json=AUTH_RESPONSE_FIXTURE)
            )
            response = sync_client.auth.sign_in("user@example.com", "pass")

        assert response.user.email == "user@example.com"

    def test_sign_up(self, sync_client: KavachSyncClient) -> None:
        with respx.mock:
            respx.post(f"{BASE_URL}/sign-up/email").mock(
                return_value=httpx.Response(200, json=AUTH_RESPONSE_FIXTURE)
            )
            response = sync_client.auth.sign_up("new@example.com", "pass", name="New")

        assert response.session.id == "sess-abc"

    def test_sign_out(self, sync_client: KavachSyncClient) -> None:
        with respx.mock:
            respx.post(f"{BASE_URL}/sign-out").mock(return_value=httpx.Response(204))
            result = sync_client.auth.sign_out()

        assert result is None

    def test_get_session(self, sync_client: KavachSyncClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/session").mock(
                return_value=httpx.Response(200, json=SESSION_FIXTURE)
            )
            session = sync_client.auth.get_session()

        assert session is not None
        assert session.token == "sess_token_xyz"

    def test_get_session_returns_none_on_401(self, sync_client: KavachSyncClient) -> None:
        with respx.mock:
            respx.get(f"{BASE_URL}/session").mock(
                return_value=httpx.Response(
                    401,
                    json={"error": {"code": "UNAUTHORIZED", "message": "Expired"}},
                )
            )
            session = sync_client.auth.get_session()

        assert session is None
