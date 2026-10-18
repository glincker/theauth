"""Dataclass types mirroring the TheAuth REST API response shapes."""

from __future__ import annotations

from theauth.types.permissions import (
    Permission,
    PermissionConstraints,
)
from theauth.types.agents import (
    Agent,
    AgentFilters,
    AgentStatus,
    AgentType,
    CreateAgentInput,
    UpdateAgentInput,
)
from theauth.types.authorize import (
    ProvenanceInput,
    ProvenanceKind,
    AuthorizeRequest,
    AuthorizeResult,
)
from theauth.types.delegation import (
    DelegateInput,
    DelegationChain,
)
from theauth.types.audit import (
    AuditEntry,
    AuditFilters,
    AuditResult,
    PaginatedAuditLogs,
)
from theauth.types.sessions import (
    AuthResponse,
    Session,
    User,
)
from theauth.types.mcp_servers import (
    McpServer,
    RegisterMcpServerInput,
)
from theauth.types.export import (
    ExportFormat,
    ExportOptions,
)

__all__ = [
    "Agent",
    "AgentFilters",
    "AgentStatus",
    "AgentType",
    "AuditEntry",
    "AuditFilters",
    "AuditResult",
    "AuthResponse",
    "AuthorizeRequest",
    "AuthorizeResult",
    "CreateAgentInput",
    "DelegateInput",
    "DelegationChain",
    "ExportFormat",
    "ExportOptions",
    "McpServer",
    "PaginatedAuditLogs",
    "Permission",
    "PermissionConstraints",
    "ProvenanceInput",
    "ProvenanceKind",
    "RegisterMcpServerInput",
    "Session",
    "UpdateAgentInput",
    "User",
]
