"""Agent identities."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional

from theauth.types.permissions import Permission


#: ``device`` is the backing agent of an IoT device. The agent routes never
#: create it; the device routes do.
AgentType = Literal["autonomous", "delegated", "service", "device"]
AgentStatus = Literal["active", "revoked", "expired"]


@dataclass
class Agent:
    """An agent identity returned by the TheAuth API."""

    id: str
    owner_id: str
    name: str
    type: AgentType
    token: str
    permissions: List[Permission]
    status: AgentStatus
    expires_at: Optional[str]
    created_at: str
    updated_at: str
    tenant_id: Optional[str] = None
    #: Sender constraint of the token (RFC 7800): ``jkt`` for a DPoP key,
    #: ``x5t#S256`` for a client certificate. ``None`` for a bearer token.
    cnf: Optional[Dict[str, str]] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Agent":
        return cls(
            id=data["id"],
            owner_id=data["ownerId"],
            name=data["name"],
            type=data["type"],
            token=data["token"],
            permissions=[Permission.from_dict(p) for p in data.get("permissions", [])],
            status=data["status"],
            expires_at=data.get("expiresAt"),
            created_at=data["createdAt"],
            updated_at=data["updatedAt"],
            tenant_id=data.get("tenantId"),
            cnf=data.get("cnf"),
        )


@dataclass
class CreateAgentInput:
    """Input for creating a new agent identity."""

    owner_id: str
    name: str
    type: AgentType
    permissions: List[Permission]
    expires_at: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    #: Bind the token to a key or certificate (RFC 7800). Build it with
    #: :func:`theauth.confirmation.dpop_confirmation` or
    #: :func:`theauth.confirmation.mtls_confirmation`.
    cnf: Optional[Dict[str, str]] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "ownerId": self.owner_id,
            "name": self.name,
            "type": self.type,
            "permissions": [p.to_dict() for p in self.permissions],
        }
        if self.expires_at is not None:
            out["expiresAt"] = self.expires_at
        if self.metadata is not None:
            out["metadata"] = self.metadata
        if self.cnf is not None:
            out["cnf"] = self.cnf
        return out


@dataclass
class UpdateAgentInput:
    """Input for updating an existing agent identity."""

    name: Optional[str] = None
    permissions: Optional[List[Permission]] = None
    expires_at: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if self.name is not None:
            out["name"] = self.name
        if self.permissions is not None:
            out["permissions"] = [p.to_dict() for p in self.permissions]
        if self.expires_at is not None:
            out["expiresAt"] = self.expires_at
        if self.metadata is not None:
            out["metadata"] = self.metadata
        return out


@dataclass
class AgentFilters:
    """Query filters for listing agents."""

    user_id: Optional[str] = None
    status: Optional[AgentStatus] = None
    type: Optional[AgentType] = None

    def to_params(self) -> Dict[str, str]:
        params: Dict[str, str] = {}
        if self.user_id is not None:
            params["userId"] = self.user_id
        if self.status is not None:
            params["status"] = self.status
        if self.type is not None:
            params["type"] = self.type
        return params
