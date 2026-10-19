"""Agent identity CRUD operations."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union
from urllib.parse import quote

from theauth._http import AsyncTransport, SyncTransport
from theauth.decisions import ExplainRequest, ExplainResult
from theauth.types import (
    Agent,
    AgentFilters,
    AuthorizeRequest,
    AuthorizeResult,
    CreateAgentInput,
    Permission,
    UpdateAgentInput,
)


class _Unset:
    """Marks "leave the binding alone" for ``rotate(cnf=...)``, since ``None`` means "unbind"."""

    def __repr__(self) -> str:
        return "UNSET"


UNSET = _Unset()
CnfArg = Union[Dict[str, str], None, _Unset]


def _rotate_body(cnf: CnfArg) -> Optional[Dict[str, Any]]:
    return None if isinstance(cnf, _Unset) else {"cnf": cnf}


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

    async def rotate(self, agent_id: str, cnf: CnfArg = UNSET) -> Agent:
        """Rotate an agent's bearer token.

        Issues a new cryptographic token and invalidates the previous one. The
        new token keeps the old ``cnf`` binding, so a stolen token is replaced by
        one the thief cannot use either.

        Args:
            agent_id: The agent's unique identifier.
            cnf: Bind the new token to another key or certificate (see
                :mod:`theauth.confirmation`), or pass ``None`` to make it a plain
                bearer token again. Leave out to keep the current binding.

        Returns:
            The updated :class:`~theauth.types.Agent` with a fresh token.
        """
        data = await self._http.request(
            "POST", f"/agents/{quote(agent_id)}/rotate", json=_rotate_body(cnf)
        )
        return Agent.from_dict(data)

    async def authorize(self, agent_id: str, request: AuthorizeRequest) -> AuthorizeResult:
        """Check whether an agent is authorized to perform an action.

        Args:
            agent_id: The agent's unique identifier.
            request: The action and resource to check.

        Returns:
            :class:`~theauth.types.AuthorizeResult` with ``allowed``, ``code`` and audit ID.
            A denial is a normal result, not an exception.
        """
        data = await self._http.request_decision(
            "/authorize",
            json={"agentId": agent_id, **request.to_dict()},
        )
        return AuthorizeResult.from_dict(data)

    async def explain(self, request: ExplainRequest) -> ExplainResult:
        """Explain an authorization decision without recording it.

        Returns the decision, the delegation chain behind the agent, the
        constraint checks and the closest grants that did not match.
        """
        data = await self._http.request("POST", "/explain", json=request.to_dict())
        return ExplainResult.from_dict(data)

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

    def rotate(self, agent_id: str, cnf: CnfArg = UNSET) -> Agent:
        """Rotate an agent's bearer token. See the async version for ``cnf``."""
        data = self._http.request(
            "POST", f"/agents/{quote(agent_id)}/rotate", json=_rotate_body(cnf)
        )
        return Agent.from_dict(data)

    def authorize(self, agent_id: str, request: AuthorizeRequest) -> AuthorizeResult:
        """Check whether an agent is authorized to perform an action."""
        data = self._http.request_decision(
            "/authorize",
            json={"agentId": agent_id, **request.to_dict()},
        )
        return AuthorizeResult.from_dict(data)

    def explain(self, request: ExplainRequest) -> ExplainResult:
        """Explain an authorization decision without recording it."""
        data = self._http.request("POST", "/explain", json=request.to_dict())
        return ExplainResult.from_dict(data)

    def get_effective_permissions(self, agent_id: str) -> List[Permission]:
        """Get the effective permissions for an agent, including delegated ones."""
        data = self._http.request(
            "GET",
            f"/delegations/{quote(agent_id)}/permissions",
        )
        return [Permission.from_dict(p) for p in data]
