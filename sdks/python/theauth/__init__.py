"""TheAuth Python SDK.

Auth OS for AI agents and humans. Wraps the TheAuth REST API with a clean,
typed Python interface.

Quickstart (async)::

    import asyncio
    from theauth import TheAuthClient
    from theauth.types import CreateAgentInput
    from theauth.permissions import read

    async def main():
        async with TheAuthClient(
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

    from theauth import TheAuthSyncClient
    from theauth.types import CreateAgentInput
    from theauth.permissions import read

    with TheAuthSyncClient(
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

from theauth.client import (
    KavachClient,
    KavachSyncClient,
    TheAuthClient,
    TheAuthSyncClient,
)
from theauth.errors import (
    AuthenticationError,
    KavachError,
    NetworkError,
    NotFoundError,
    PermissionError,
    RateLimitError,
    ServerError,
    TheAuthError,
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
    "TheAuthClient",
    "TheAuthSyncClient",
    # Clients (deprecated aliases, use TheAuthClient / TheAuthSyncClient instead)
    "KavachClient",
    "KavachSyncClient",
    # Errors
    "TheAuthError",
    # Errors (deprecated alias, use TheAuthError instead)
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
