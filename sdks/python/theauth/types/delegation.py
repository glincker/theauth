"""Delegation chains."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from theauth.types.agents import Agent
from theauth.types.permissions import Permission


@dataclass
class DelegateInput:
    """Input for creating a delegation from one agent to another."""

    from_agent: str
    to_agent: str
    permissions: List[Permission]
    expires_at: str
    max_depth: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "fromAgent": self.from_agent,
            "toAgent": self.to_agent,
            "permissions": [p.to_dict() for p in self.permissions],
            "expiresAt": self.expires_at,
        }
        if self.max_depth is not None:
            out["maxDepth"] = self.max_depth
        return out


@dataclass
class DelegationChain:
    """A single delegation link between two agents."""

    id: str
    from_agent: str
    to_agent: str
    permissions: List[Permission]
    expires_at: str
    depth: int
    created_at: str
    #: Human owning the root agent of the chain, the accountable principal.
    root_owner_id: Optional[str] = None
    #: Agent ids from the root agent to this link.
    path: Optional[List[str]] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DelegationChain":
        return cls(
            id=data["id"],
            from_agent=data["fromAgent"],
            to_agent=data["toAgent"],
            permissions=[Permission.from_dict(p) for p in data.get("permissions", [])],
            expires_at=data["expiresAt"],
            depth=data["depth"],
            created_at=data["createdAt"],
            root_owner_id=data.get("rootOwnerId"),
            path=data.get("path"),
        )
