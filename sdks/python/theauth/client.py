"""Main async and sync client classes for TheAuth."""

from __future__ import annotations

from typing import Any, Dict, Optional

import httpx

from theauth._http import AsyncTransport, SyncTransport
from theauth.agents import AsyncAgentsResource, SyncAgentsResource
from theauth.approvals import AsyncApprovalsResource, SyncApprovalsResource
from theauth.audit import AsyncAuditResource, SyncAuditResource
from theauth.auth import AsyncAuthResource, SyncAuthResource
from theauth.delegation import AsyncDelegationResource, SyncDelegationResource
from theauth.devices.resource import (
    AsyncDeviceApiResource,
    AsyncDevicesResource,
    SyncDeviceApiResource,
    SyncDevicesResource,
)
from theauth.mcp import AsyncMcpResource, SyncMcpResource
from theauth.types import AuthorizeRequest, AuthorizeResult


def _clean_params(params: Optional[Dict[str, Any]]) -> Optional[Dict[str, str]]:
    if not params:
        return None
    out: Dict[str, str] = {}
    for key, value in params.items():
        if value is None:
            continue
        if isinstance(value, bool):
            out[key] = "true" if value else "false"
        else:
            out[key] = str(value)
    return out or None


class TheAuthClient:
    """Async TheAuth client.

    All methods are coroutines and must be awaited. Use :class:`TheAuthSyncClient`
    if you need a blocking interface.

    Args:
        base_url: Base URL of your TheAuth deployment, e.g.
            ``"https://your-app.com/api/theauth"``.
        token: Optional bearer token sent with every request. Can be a user
            session token or an agent token. Individual methods that accept a
            ``token`` argument override this value for that call only.
        headers: Additional HTTP headers merged into every request.
        timeout: HTTP request timeout in seconds. Defaults to 30.
        auth: Optional :class:`httpx.Auth`, e.g. :class:`theauth.dpop.DPoPAuth`
            for DPoP (RFC 9449) sender-constrained tokens.

    Example::

        import asyncio
        from theauth import TheAuthClient
        from theauth.types import CreateAgentInput
        from theauth.permissions import read

        async def main():
            async with TheAuthClient(
                base_url="https://my-app.com/api/theauth",
                token="ta_...",
            ) as client:
                agent = await client.agents.create(
                    CreateAgentInput(
                        owner_id="user-123",
                        name="github-reader",
                        type="autonomous",
                        permissions=[read("mcp:github:*")],
                    )
                )
                print(agent.id, agent.token)

        asyncio.run(main())
    """

    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 30.0,
        auth: Optional[httpx.Auth] = None,
    ) -> None:
        self._transport = AsyncTransport(
            base_url=base_url,
            token=token,
            headers=headers,
            timeout=timeout,
            auth=auth,
        )
        self.agents = AsyncAgentsResource(self._transport)
        self.auth = AsyncAuthResource(self._transport)
        self.audit = AsyncAuditResource(self._transport)
        self.delegation = AsyncDelegationResource(self._transport)
        self.mcp = AsyncMcpResource(self._transport)
        self.approvals = AsyncApprovalsResource(self._transport)
        #: Device registry (admin routes, ``/devices``).
        self.devices = AsyncDevicesResource(self._transport)
        #: Calls a device makes as itself (``/device/*``).
        self.device = AsyncDeviceApiResource(self._transport)

    async def authorize(
        self,
        agent_id: str,
        request: AuthorizeRequest,
    ) -> AuthorizeResult:
        """Check whether an agent may perform an action.

        Convenience method that delegates to ``client.agents.authorize``.

        Args:
            agent_id: The agent's unique identifier.
            request: The action and resource to check.

        Returns:
            :class:`~theauth.types.AuthorizeResult`.
        """
        return await self.agents.authorize(agent_id, request)

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
    ) -> Any:
        """Call any route, e.g. a plugin endpoint declared with ``defineEndpoint``.

        Args:
            method: HTTP method.
            path: Path relative to ``base_url``, e.g. ``"/auth/team/invite"``.
            params: Query string parameters. ``None`` values are dropped.
            json: JSON request body.

        Returns:
            The parsed JSON body, or ``None`` for 204 responses.

        Raises:
            ValidationError: Input rejected (``error.issues`` available).
            TheAuthError: Any other non-2xx response, mapped by status.
        """
        return await self._transport.request(
            method.upper(), path, json=json, params=_clean_params(params), unwrap_data=False
        )

    async def close(self) -> None:
        """Close the underlying HTTP connections."""
        await self._transport.close()

    async def __aenter__(self) -> "TheAuthClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()


class TheAuthSyncClient:
    """Synchronous TheAuth client.

    Wraps the same API surface as :class:`TheAuthClient` but uses blocking
    :mod:`httpx` calls. Suitable for scripts, CLIs, and frameworks without an
    async event loop.

    Args:
        base_url: Base URL of your TheAuth deployment.
        token: Optional bearer token sent with every request.
        headers: Additional HTTP headers merged into every request.
        timeout: HTTP request timeout in seconds. Defaults to 30.
        auth: Optional :class:`httpx.Auth`, e.g. :class:`theauth.dpop.DPoPAuth`
            for DPoP (RFC 9449) sender-constrained tokens.

    Example::

        from theauth import TheAuthSyncClient
        from theauth.types import CreateAgentInput
        from theauth.permissions import read

        with TheAuthSyncClient(
            base_url="https://my-app.com/api/theauth",
            token="ta_...",
        ) as client:
            agent = client.agents.create(
                CreateAgentInput(
                    owner_id="user-123",
                    name="github-reader",
                    type="autonomous",
                    permissions=[read("mcp:github:*")],
                )
            )
            print(agent.id, agent.token)
    """

    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 30.0,
        auth: Optional[httpx.Auth] = None,
    ) -> None:
        self._transport = SyncTransport(
            base_url=base_url,
            token=token,
            headers=headers,
            timeout=timeout,
            auth=auth,
        )
        self.agents = SyncAgentsResource(self._transport)
        self.auth = SyncAuthResource(self._transport)
        self.audit = SyncAuditResource(self._transport)
        self.delegation = SyncDelegationResource(self._transport)
        self.mcp = SyncMcpResource(self._transport)
        self.approvals = SyncApprovalsResource(self._transport)
        #: Device registry (admin routes, ``/devices``).
        self.devices = SyncDevicesResource(self._transport)
        #: Calls a device makes as itself (``/device/*``).
        self.device = SyncDeviceApiResource(self._transport)

    def authorize(
        self,
        agent_id: str,
        request: AuthorizeRequest,
    ) -> AuthorizeResult:
        """Check whether an agent may perform an action."""
        return self.agents.authorize(agent_id, request)

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
    ) -> Any:
        """Call any route, e.g. a plugin endpoint declared with ``defineEndpoint``.

        Args:
            method: HTTP method.
            path: Path relative to ``base_url``, e.g. ``"/auth/team/invite"``.
            params: Query string parameters. ``None`` values are dropped.
            json: JSON request body.

        Returns:
            The parsed JSON body, or ``None`` for 204 responses.

        Raises:
            ValidationError: Input rejected (``error.issues`` available).
            TheAuthError: Any other non-2xx response, mapped by status.
        """
        return self._transport.request(
            method.upper(), path, json=json, params=_clean_params(params), unwrap_data=False
        )

    def close(self) -> None:
        """Close the underlying HTTP connections."""
        self._transport.close()

    def __enter__(self) -> "TheAuthSyncClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


# Deprecated: use TheAuthClient instead. Will be removed in a future major version.
# Deprecated: use TheAuthSyncClient instead. Will be removed in a future major version.
