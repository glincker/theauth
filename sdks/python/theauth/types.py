"""Dataclass types mirroring the TheAuth REST API response shapes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------


@dataclass
class PermissionConstraints:
    """Optional constraints attached to a permission grant."""

    max_calls_per_hour: Optional[int] = None
    allowed_arg_patterns: Optional[List[str]] = None
    require_approval: Optional[bool] = None
    time_window_start: Optional[str] = None
    time_window_end: Optional[str] = None
    ip_allowlist: Optional[List[str]] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PermissionConstraints":
        tw = data.get("timeWindow") or {}
        return cls(
            max_calls_per_hour=data.get("maxCallsPerHour"),
            allowed_arg_patterns=data.get("allowedArgPatterns"),
            require_approval=data.get("requireApproval"),
            time_window_start=tw.get("start"),
            time_window_end=tw.get("end"),
            ip_allowlist=data.get("ipAllowlist"),
        )

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if self.max_calls_per_hour is not None:
            out["maxCallsPerHour"] = self.max_calls_per_hour
        if self.allowed_arg_patterns is not None:
            out["allowedArgPatterns"] = self.allowed_arg_patterns
        if self.require_approval is not None:
            out["requireApproval"] = self.require_approval
        if self.time_window_start is not None or self.time_window_end is not None:
            out["timeWindow"] = {
                "start": self.time_window_start,
                "end": self.time_window_end,
            }
        if self.ip_allowlist is not None:
            out["ipAllowlist"] = self.ip_allowlist
        return out


@dataclass
class Permission:
    """A single permission grant: resource pattern + allowed actions."""

    resource: str
    actions: List[str]
    constraints: Optional[PermissionConstraints] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Permission":
        constraints = None
        if data.get("constraints"):
            constraints = PermissionConstraints.from_dict(data["constraints"])
        return cls(
            resource=data["resource"],
            actions=data["actions"],
            constraints=constraints,
        )

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "resource": self.resource,
            "actions": self.actions,
        }
        if self.constraints is not None:
            out["constraints"] = self.constraints.to_dict()
        return out


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------

AgentType = Literal["autonomous", "delegated", "service"]
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


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------


@dataclass
class AuthorizeRequest:
    """A request to check whether an agent may perform an action."""

    action: str
    resource: str
    arguments: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "action": self.action,
            "resource": self.resource,
        }
        if self.arguments is not None:
            out["arguments"] = self.arguments
        return out


@dataclass
class AuthorizeResult:
    """Result of an authorization check."""

    allowed: bool
    audit_id: str
    reason: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthorizeResult":
        return cls(
            allowed=data["allowed"],
            audit_id=data["auditId"],
            reason=data.get("reason"),
        )


# ---------------------------------------------------------------------------
# Delegation
# ---------------------------------------------------------------------------


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
        )


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

AuditResult = Literal["allowed", "denied", "rate_limited"]


@dataclass
class AuditEntry:
    """A single audit log record."""

    id: str
    agent_id: str
    user_id: str
    action: str
    resource: str
    parameters: Dict[str, Any]
    result: AuditResult
    duration_ms: int
    timestamp: str
    reason: Optional[str] = None
    tokens_cost: Optional[float] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEntry":
        return cls(
            id=data["id"],
            agent_id=data["agentId"],
            user_id=data["userId"],
            action=data["action"],
            resource=data["resource"],
            parameters=data.get("parameters", {}),
            result=data["result"],
            duration_ms=data["durationMs"],
            timestamp=data["timestamp"],
            reason=data.get("reason"),
            tokens_cost=data.get("tokensCost"),
        )


@dataclass
class AuditFilters:
    """Query filters for the audit log."""

    agent_id: Optional[str] = None
    user_id: Optional[str] = None
    since: Optional[str] = None
    until: Optional[str] = None
    actions: Optional[List[str]] = None
    result: Optional[AuditResult] = None
    limit: Optional[int] = None
    offset: Optional[int] = None

    def to_params(self) -> Dict[str, str]:
        params: Dict[str, str] = {}
        if self.agent_id is not None:
            params["agentId"] = self.agent_id
        if self.user_id is not None:
            params["userId"] = self.user_id
        if self.since is not None:
            params["since"] = self.since
        if self.until is not None:
            params["until"] = self.until
        if self.actions is not None:
            params["actions"] = ",".join(self.actions)
        if self.result is not None:
            params["result"] = self.result
        if self.limit is not None:
            params["limit"] = str(self.limit)
        if self.offset is not None:
            params["offset"] = str(self.offset)
        return params


@dataclass
class PaginatedAuditLogs:
    """Paginated audit log response."""

    entries: List[AuditEntry]
    total: Optional[int] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PaginatedAuditLogs":
        return cls(
            entries=[AuditEntry.from_dict(e) for e in data.get("entries", [])],
            total=data.get("total"),
        )


# ---------------------------------------------------------------------------
# Auth / Sessions
# ---------------------------------------------------------------------------


@dataclass
class User:
    """A human user account."""

    id: str
    email: str
    created_at: str
    name: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "User":
        return cls(
            id=data["id"],
            email=data["email"],
            created_at=data["createdAt"],
            name=data.get("name"),
        )


@dataclass
class Session:
    """An active session token for a human user."""

    id: str
    user_id: str
    token: str
    expires_at: str
    created_at: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Session":
        return cls(
            id=data["id"],
            user_id=data["userId"],
            token=data["token"],
            expires_at=data["expiresAt"],
            created_at=data["createdAt"],
        )


@dataclass
class AuthResponse:
    """Returned by sign-in and sign-up endpoints."""

    user: User
    session: Session

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthResponse":
        # The API wraps the payload in { success: true, data: { user, session } }
        payload = data.get("data", data)
        return cls(
            user=User.from_dict(payload["user"]),
            session=Session.from_dict(payload["session"]),
        )


# ---------------------------------------------------------------------------
# MCP servers
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Export options
# ---------------------------------------------------------------------------

ExportFormat = Literal["json", "csv"]


@dataclass
class ExportOptions:
    """Options for exporting audit logs."""

    format: ExportFormat = "json"
    since: Optional[str] = None
    until: Optional[str] = None

    def to_params(self) -> Dict[str, str]:
        params: Dict[str, str] = {"format": self.format}
        if self.since is not None:
            params["since"] = self.since
        if self.until is not None:
            params["until"] = self.until
        return params
