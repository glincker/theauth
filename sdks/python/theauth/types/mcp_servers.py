"""MCP server registrations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional



@dataclass
class RegisterMcpServerInput:
    """Input for registering an MCP server."""

    name: str
    endpoint: str
    tools: List[str]
    auth_required: bool = True
    rate_limit_rpm: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "name": self.name,
            "endpoint": self.endpoint,
            "tools": self.tools,
            "authRequired": self.auth_required,
        }
        if self.rate_limit_rpm is not None:
            out["rateLimit"] = {"rpm": self.rate_limit_rpm}
        return out


@dataclass
class McpServer:
    """A registered MCP server."""

    id: str
    name: str
    endpoint: str
    tools: List[str]
    auth_required: bool
    created_at: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "McpServer":
        return cls(
            id=data["id"],
            name=data["name"],
            endpoint=data["endpoint"],
            tools=data.get("tools", []),
            auth_required=data.get("authRequired", True),
            created_at=data["createdAt"],
        )
