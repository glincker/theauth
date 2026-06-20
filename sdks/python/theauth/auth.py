"""Authentication helpers for human users (sign-in, sign-up, sessions)."""

from __future__ import annotations

from typing import Optional

from theauth._http import AsyncTransport, SyncTransport
from theauth.types import AuthorizeRequest, AuthorizeResult, AuthResponse, Session


class AsyncAuthResource:
    """Async human authentication operations."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._http = transport

    async def sign_in(self, email: str, password: str) -> AuthResponse:
        """Sign in with email and password.

        Args:
            email: The user's email address.
            password: The user's password.

        Returns:
            :class:`~theauth.types.AuthResponse` containing the user and session.
        """
        data = await self._http.request(
            "POST",
            "/sign-in/email",
            json={"email": email, "password": password},
        )
        return AuthResponse.from_dict(data)

    async def sign_up(
        self,
        email: str,
        password: str,
        name: Optional[str] = None,
    ) -> AuthResponse:
        """Create a new account with email and password.

        Args:
            email: The new user's email address.
            password: The new user's password.
            name: Optional display name.

        Returns:
            :class:`~theauth.types.AuthResponse` containing the user and session.
        """
        body = {"email": email, "password": password}
        if name is not None:
            body["name"] = name
        data = await self._http.request("POST", "/sign-up/email", json=body)
        return AuthResponse.from_dict(data)

    async def sign_out(self, token: Optional[str] = None) -> None:
        """Sign out the current session.

        Args:
            token: Session token to revoke. When omitted the token configured
                on the client is used (passed via ``Authorization`` header).
        """
        extra_headers = {"Authorization": f"Bearer {token}"} if token else None
        await self._http.request(
            "POST",
            "/sign-out",
            extra_headers=extra_headers,
        )

    async def get_session(self, token: Optional[str] = None) -> Optional[Session]:
        """Retrieve the current session.

        Args:
            token: Session token to look up. When omitted the token configured
                on the client is used.

        Returns:
            :class:`~theauth.types.Session` if the token is valid,
            ``None`` if it has expired or does not exist.
        """
        from theauth.errors import AuthenticationError, NotFoundError

        extra_headers = {"Authorization": f"Bearer {token}"} if token else None
        try:
            data = await self._http.request(
                "GET",
                "/session",
                extra_headers=extra_headers,
            )
            return Session.from_dict(data)
        except (AuthenticationError, NotFoundError):
            return None

    async def authorize_by_token(
        self,
        agent_token: str,
        request: AuthorizeRequest,
    ) -> AuthorizeResult:
        """Authorize an action using an agent bearer token directly.

        Useful when you have the raw agent token rather than its ID.

        Args:
            agent_token: The agent's ``kv_...`` bearer token.
            request: The action and resource to check.

        Returns:
            :class:`~theauth.types.AuthorizeResult`.
        """
        data = await self._http.request(
            "POST",
            "/authorize",
            json=request.to_dict(),
            extra_headers={"Authorization": f"Bearer {agent_token}"},
        )
        return AuthorizeResult.from_dict(data)


class SyncAuthResource:
    """Sync human authentication operations."""

    def __init__(self, transport: SyncTransport) -> None:
        self._http = transport

    def sign_in(self, email: str, password: str) -> AuthResponse:
        """Sign in with email and password."""
        data = self._http.request(
            "POST",
            "/sign-in/email",
            json={"email": email, "password": password},
        )
        return AuthResponse.from_dict(data)

    def sign_up(
        self,
        email: str,
        password: str,
        name: Optional[str] = None,
    ) -> AuthResponse:
        """Create a new account with email and password."""
        body = {"email": email, "password": password}
        if name is not None:
            body["name"] = name
        data = self._http.request("POST", "/sign-up/email", json=body)
        return AuthResponse.from_dict(data)

    def sign_out(self, token: Optional[str] = None) -> None:
        """Sign out the current session."""
        extra_headers = {"Authorization": f"Bearer {token}"} if token else None
        self._http.request("POST", "/sign-out", extra_headers=extra_headers)

    def get_session(self, token: Optional[str] = None) -> Optional[Session]:
        """Retrieve the current session."""
        from theauth.errors import AuthenticationError, NotFoundError

        extra_headers = {"Authorization": f"Bearer {token}"} if token else None
        try:
            data = self._http.request("GET", "/session", extra_headers=extra_headers)
            return Session.from_dict(data)
        except (AuthenticationError, NotFoundError):
            return None

    def authorize_by_token(
        self,
        agent_token: str,
        request: AuthorizeRequest,
    ) -> AuthorizeResult:
        """Authorize an action using an agent bearer token directly."""
        data = self._http.request(
            "POST",
            "/authorize",
            json=request.to_dict(),
            extra_headers={"Authorization": f"Bearer {agent_token}"},
        )
        return AuthorizeResult.from_dict(data)
