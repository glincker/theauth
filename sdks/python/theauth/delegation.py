"""Delegation chain management."""

from __future__ import annotations

from typing import List
from urllib.parse import quote

from theauth._http import AsyncTransport, SyncTransport
from theauth.types import DelegateInput, DelegationChain, Permission


class AsyncDelegationResource:
    """Async delegation chain operations."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._http = transport

    async def create(self, input: DelegateInput) -> DelegationChain:
        """Create a delegation from one agent to another.

        The delegated agent receives a subset of the granting agent's
        permissions, subject to the depth limit.

        Args:
            input: Delegation parameters including agents, permissions, and
                expiry.

        Returns:
            The newly created :class:`~theauth.types.DelegationChain`.
        """
        data = await self._http.request("POST", "/delegations", json=input.to_dict())
        return DelegationChain.from_dict(data)

    async def list_chains(self, agent_id: str) -> List[DelegationChain]:
        """List all delegation chains where the agent is a participant.

        Args:
            agent_id: The agent's unique identifier.

        Returns:
            List of :class:`~theauth.types.DelegationChain` objects.
        """
        data = await self._http.request("GET", f"/delegations/{quote(agent_id)}")
        return [DelegationChain.from_dict(d) for d in data]

    async def revoke(self, delegation_id: str) -> None:
        """Revoke a specific delegation chain.

        Args:
            delegation_id: The delegation's unique identifier.
        """
        await self._http.request("DELETE", f"/delegations/{quote(delegation_id)}")

    async def get_effective_permissions(self, agent_id: str) -> List[Permission]:
        """Get the effective permissions for an agent, merging own and delegated.

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


class SyncDelegationResource:
    """Sync delegation chain operations."""

    def __init__(self, transport: SyncTransport) -> None:
        self._http = transport

    def create(self, input: DelegateInput) -> DelegationChain:
        """Create a delegation from one agent to another."""
        data = self._http.request("POST", "/delegations", json=input.to_dict())
        return DelegationChain.from_dict(data)

    def list_chains(self, agent_id: str) -> List[DelegationChain]:
        """List all delegation chains where the agent is a participant."""
        data = self._http.request("GET", f"/delegations/{quote(agent_id)}")
        return [DelegationChain.from_dict(d) for d in data]

    def revoke(self, delegation_id: str) -> None:
        """Revoke a specific delegation chain."""
        self._http.request("DELETE", f"/delegations/{quote(delegation_id)}")

    def get_effective_permissions(self, agent_id: str) -> List[Permission]:
        """Get the effective permissions for an agent, merging own and delegated."""
        data = self._http.request(
            "GET",
            f"/delegations/{quote(agent_id)}/permissions",
        )
        return [Permission.from_dict(p) for p in data]
