"""TheAuth Python SDK.

Auth OS for AI agents and humans. Wraps the TheAuth REST API with a clean,
typed Python interface.

Quickstart (async)::

    import asyncio
    from theauth import KavachClient
    from theauth.types import CreateAgentInput
    from theauth.permissions import read

    async def main():
        async with KavachClient(
            base_url="https://your-app.com/api/kavach",
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
            print(agent.id)

    asyncio.run(main())

Quickstart (sync)::

    from theauth import KavachSyncClient
    from theauth.types import CreateAgentInput
    from theauth.permissions import read

    with KavachSyncClient(
        base_url="https://your-app.com/api/kavach",
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
        print(agent.id)
"""

from theauth.client import KavachClient, KavachSyncClient
from theauth.errors import (
    AuthenticationError,
    KavachError,
    NetworkError,
    NotFoundError,
    PermissionError,
    RateLimitError,
    ServerError,
)
from theauth.types import (
    Agent,
    AgentFilters,
    AuditEntry,
    AuditFilters,
    AuthorizeRequest,
    AuthorizeResult,
    AuthResponse,
    CreateAgentInput,
    DelegateInput,
    DelegationChain,
    ExportOptions,
    McpServer,
    Permission,
    PermissionConstraints,
    RegisterMcpServerInput,
    Session,
    UpdateAgentInput,
    User,
)

__all__ = [
    # Clients
    "KavachClient",
    "KavachSyncClient",
    # Errors
    "KavachError",
    "AuthenticationError",
    "PermissionError",
    "NotFoundError",
    "RateLimitError",
    "ServerError",
    "NetworkError",
    # Types
    "Agent",
    "AgentFilters",
    "AuditEntry",
    "AuditFilters",
    "AuthorizeRequest",
    "AuthorizeResult",
    "AuthResponse",
    "CreateAgentInput",
    "DelegateInput",
    "DelegationChain",
    "ExportOptions",
    "McpServer",
    "Permission",
    "PermissionConstraints",
    "RegisterMcpServerInput",
    "Session",
    "UpdateAgentInput",
    "User",
]

__version__ = "0.1.0"
