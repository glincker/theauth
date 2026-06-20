"""Agent identity CRUD operations."""

from __future__ import annotations

from typing import List, Optional
from urllib.parse import quote

from theauth._http import AsyncTransport, SyncTransport
from theauth.types import (
    Agent,
    AgentFilters,
    AuthorizeRequest,
    AuthorizeResult,
    CreateAgentInput,
    Permission,
    UpdateAgentInput,
)


class AsyncAgentsResource:
    """Async agent identity management."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._http = transport

    async def create(self, input: CreateAgentInput) -> Agent:
        """Create a new agent identity.

        Args:
            input: Agent creation parameters.

        Returns:
            The newly created :class:`~theauth.types.Agent`.
        """
        data = await self._http.request("POST", "/agents", json=input.to_dict())
        return Agent.from_dict(data)

    async def list(self, filters: Optional[AgentFilters] = None) -> List[Agent]:
        """List agent identities, optionally filtered.

        Args:
            filters: Optional query filters (user_id, status, type).

        Returns:
            List of :class:`~theauth.types.Agent` objects.
        """
        params = filters.to_params() if filters else None
        data = await self._http.request("GET", "/agents", params=params)
        return [Agent.from_dict(a) for a in data]

    async def get(self, agent_id: str) -> Optional[Agent]:
        """Get an agent by ID. Returns ``None`` if not found.

        Args:
            agent_id: The agent's unique identifier.
        """
        from theauth.errors import NotFoundError

        try:
            data = await self._http.request("GET", f"/agents/{quote(agent_id)}")
            return Agent.from_dict(data)
        except NotFoundError:
            return None

    async def update(self, agent_id: str, input: UpdateAgentInput) -> Agent:
        """Update an existing agent identity.

        Args:
            agent_id: The agent's unique identifier.
            input: Fields to update (all optional).

        Returns:
            The updated :class:`~theauth.types.Agent`.
        """
        data = await self._http.request(
            "PATCH",
            f"/agents/{quote(agent_id)}",
            json=input.to_dict(),
        )
        return Agent.from_dict(data)

    async def revoke(self, agent_id: str) -> None:
        """Revoke (delete) an agent identity.

        Args:
            agent_id: The agent's unique identifier.
        """
        await self._http.request("DELETE", f"/agents/{quote(agent_id)}")

    async def rotate(self, agent_id: str) -> Agent:
        """Rotate an agent's bearer token.

        Issues a new cryptographic token and invalidates the previous one.

        Args:
            agent_id: The agent's unique identifier.

        Returns:
            The updated :class:`~theauth.types.Agent` with a fresh token.
        """
        data = await self._http.request("POST", f"/agents/{quote(agent_id)}/rotate")
        return Agent.from_dict(data)

    async def authorize(self, agent_id: str, request: AuthorizeRequest) -> AuthorizeResult:
        """Check whether an agent is authorized to perform an action.

        Args:
            agent_id: The agent's unique identifier.
            request: The action and resource to check.

        Returns:
            :class:`~theauth.types.AuthorizeResult` with ``allowed`` flag and audit ID.
        """
        data = await self._http.request(
            "POST",
            f"/agents/{quote(agent_id)}/authorize",
            json=request.to_dict(),
        )
        return AuthorizeResult.from_dict(data)

    async def get_effective_permissions(self, agent_id: str) -> List[Permission]:
        """Get the effective permissions for an agent, including delegated ones.

        Args:
            agent_id: The agent's unique identifier.

        Returns:
            Flattened list of :class:`~theauth.types.Permission` objects.
        """
        data = await self._http.request(
            "GET",
            f"/delegations/{quote(agent_id)}/permissions",
        )
        return [Permission.from_dict(p) for p in data]


class SyncAgentsResource:
    """Sync agent identity management."""

    def __init__(self, transport: SyncTransport) -> None:
        self._http = transport

    def create(self, input: CreateAgentInput) -> Agent:
        """Create a new agent identity."""
        data = self._http.request("POST", "/agents", json=input.to_dict())
        return Agent.from_dict(data)

    def list(self, filters: Optional[AgentFilters] = None) -> List[Agent]:
        """List agent identities, optionally filtered."""
        params = filters.to_params() if filters else None
        data = self._http.request("GET", "/agents", params=params)
        return [Agent.from_dict(a) for a in data]

    def get(self, agent_id: str) -> Optional[Agent]:
        """Get an agent by ID. Returns ``None`` if not found."""
        from theauth.errors import NotFoundError

        try:
            data = self._http.request("GET", f"/agents/{quote(agent_id)}")
            return Agent.from_dict(data)
        except NotFoundError:
            return None

    def update(self, agent_id: str, input: UpdateAgentInput) -> Agent:
        """Update an existing agent identity."""
        data = self._http.request(
            "PATCH",
            f"/agents/{quote(agent_id)}",
            json=input.to_dict(),
        )
        return Agent.from_dict(data)

    def revoke(self, agent_id: str) -> None:
        """Revoke (delete) an agent identity."""
        self._http.request("DELETE", f"/agents/{quote(agent_id)}")

    def rotate(self, agent_id: str) -> Agent:
        """Rotate an agent's bearer token."""
        data = self._http.request("POST", f"/agents/{quote(agent_id)}/rotate")
        return Agent.from_dict(data)

    def authorize(self, agent_id: str, request: AuthorizeRequest) -> AuthorizeResult:
        """Check whether an agent is authorized to perform an action."""
        data = self._http.request(
            "POST",
            f"/agents/{quote(agent_id)}/authorize",
            json=request.to_dict(),
        )
        return AuthorizeResult.from_dict(data)

    def get_effective_permissions(self, agent_id: str) -> List[Permission]:
        """Get the effective permissions for an agent, including delegated ones."""
        data = self._http.request(
            "GET",
            f"/delegations/{quote(agent_id)}/permissions",
        )
        return [Permission.from_dict(p) for p in data]
