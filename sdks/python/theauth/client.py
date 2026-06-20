"""Main async and sync client classes for TheAuth."""

from __future__ import annotations

from typing import Any, Dict, Optional

from theauth._http import AsyncTransport, SyncTransport
from theauth.agents import AsyncAgentsResource, SyncAgentsResource
from theauth.audit import AsyncAuditResource, SyncAuditResource
from theauth.auth import AsyncAuthResource, SyncAuthResource
from theauth.delegation import AsyncDelegationResource, SyncDelegationResource
from theauth.types import AuthorizeRequest, AuthorizeResult


class KavachClient:
    """Async TheAuth client.

    All methods are coroutines and must be awaited. Use :class:`KavachSyncClient`
    if you need a blocking interface.

    Args:
        base_url: Base URL of your TheAuth deployment, e.g.
            ``"https://your-app.com/api/kavach"``.
        token: Optional bearer token sent with every request. Can be a user
            session token or an agent token. Individual methods that accept a
            ``token`` argument override this value for that call only.
        headers: Additional HTTP headers merged into every request.
        timeout: HTTP request timeout in seconds. Defaults to 30.

    Example::

        import asyncio
        from theauth import KavachClient
        from theauth.types import CreateAgentInput
        from theauth.permissions import read

        async def main():
            async with KavachClient(
                base_url="https://my-app.com/api/kavach",
                token="kv_...",
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
    ) -> None:
        self._transport = AsyncTransport(
            base_url=base_url,
            token=token,
            headers=headers,
            timeout=timeout,
        )
        self.agents = AsyncAgentsResource(self._transport)
        self.auth = AsyncAuthResource(self._transport)
        self.audit = AsyncAuditResource(self._transport)
        self.delegation = AsyncDelegationResource(self._transport)

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

    async def close(self) -> None:
        """Close the underlying HTTP connections."""
        await self._transport.close()

    async def __aenter__(self) -> "KavachClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()


class KavachSyncClient:
    """Synchronous TheAuth client.

    Wraps the same API surface as :class:`KavachClient` but uses blocking
    :mod:`httpx` calls. Suitable for scripts, CLIs, and frameworks without an
    async event loop.

    Args:
        base_url: Base URL of your TheAuth deployment.
        token: Optional bearer token sent with every request.
        headers: Additional HTTP headers merged into every request.
        timeout: HTTP request timeout in seconds. Defaults to 30.

    Example::

        from theauth import KavachSyncClient
        from theauth.types import CreateAgentInput
        from theauth.permissions import read

        with KavachSyncClient(
            base_url="https://my-app.com/api/kavach",
            token="kv_...",
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
    ) -> None:
        self._transport = SyncTransport(
            base_url=base_url,
            token=token,
            headers=headers,
            timeout=timeout,
        )
        self.agents = SyncAgentsResource(self._transport)
        self.auth = SyncAuthResource(self._transport)
        self.audit = SyncAuditResource(self._transport)
        self.delegation = SyncDelegationResource(self._transport)

    def authorize(
        self,
        agent_id: str,
        request: AuthorizeRequest,
    ) -> AuthorizeResult:
        """Check whether an agent may perform an action."""
        return self.agents.authorize(agent_id, request)

    def close(self) -> None:
        """Close the underlying HTTP connections."""
        self._transport.close()

    def __enter__(self) -> "KavachSyncClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
