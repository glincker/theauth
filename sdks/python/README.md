# kavachos

Python SDK for [KavachOS](https://kavachos.dev). Auth OS for AI agents and humans.

[![PyPI](https://img.shields.io/pypi/v/kavachos)](https://pypi.org/project/kavachos/)
[![Python](https://img.shields.io/pypi/pyversions/kavachos)](https://pypi.org/project/kavachos/)
[![License](https://img.shields.io/badge/license-MIT-blue)](../../LICENSE)

---

## Install

```bash
pip install kavachos
```

Requires Python 3.9+ and `httpx`.

---

## Quick start

### Async (recommended)

```python
import asyncio
from kavachos import KavachClient
from kavachos.types import CreateAgentInput
from kavachos.permissions import read, with_approval, execute

async def main():
    async with KavachClient(
        base_url="https://your-app.com/api/kavach",
        token="kv_...",
    ) as client:
        # Create an agent
        agent = await client.agents.create(
            CreateAgentInput(
                owner_id="user-123",
                name="github-reader",
                type="autonomous",
                permissions=[
                    read("mcp:github:*"),
                    with_approval(execute("mcp:deploy:production")),
                ],
            )
        )

        # Check authorization
        result = await client.authorize(
            agent.id,
            AuthorizeRequest(action="read", resource="mcp:github:repos"),
        )
        print(result.allowed)  # True

asyncio.run(main())
```

### Sync

```python
from kavachos import KavachSyncClient
from kavachos.types import CreateAgentInput
from kavachos.permissions import read

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
    print(agent.id, agent.token)
```

---

## Authentication

Sign in and sign up with email and password.

```python
async with KavachClient(base_url="https://your-app.com/api/kavach") as client:
    # Sign up
    auth = await client.auth.sign_up(
        email="user@example.com",
        password="secure-password",
        name="Alice",
    )
    print(auth.user.id)
    print(auth.session.token)

    # Sign in later
    auth = await client.auth.sign_in(
        email="user@example.com",
        password="secure-password",
    )

    # Get current session
    session = await client.auth.get_session(token=auth.session.token)

    # Sign out
    await client.auth.sign_out()
```

---

## Agent management

```python
from kavachos.types import AgentFilters, UpdateAgentInput

# List agents for a user
agents = await client.agents.list(AgentFilters(user_id="user-123", status="active"))

# Get a single agent (returns None if not found)
agent = await client.agents.get("agent-abc123")

# Update name or permissions
agent = await client.agents.update(
    "agent-abc123",
    UpdateAgentInput(name="better-name"),
)

# Rotate the token (old token is immediately invalidated)
agent = await client.agents.rotate("agent-abc123")
print(agent.token)  # kv_new_...

# Revoke (delete) an agent
await client.agents.revoke("agent-abc123")
```

---

## Authorization

```python
from kavachos.types import AuthorizeRequest

# Authorize by agent ID (requires admin/service token on the client)
result = await client.authorize(
    "agent-abc123",
    AuthorizeRequest(
        action="execute",
        resource="mcp:deploy:production",
        arguments={"version": "1.2.3"},
    ),
)
print(result.allowed)   # True / False
print(result.audit_id)  # "aud_..."

# Authorize using the agent's own bearer token (no admin token needed)
result = await client.auth.authorize_by_token(
    agent_token="kv_agent_xyz",
    request=AuthorizeRequest(action="read", resource="mcp:github:repos"),
)
```

---

## Permissions helpers

The `kavachos.permissions` module provides shorthand constructors.

```python
from kavachos.permissions import (
    read,
    write,
    execute,
    read_write,
    full_access,
    with_approval,
    rate_limited,
)
from kavachos.types import PermissionConstraints

# Simple read permission
perm = read("mcp:github:*")

# Require human approval before execution
perm = with_approval(execute("mcp:deploy:production"))

# Limit to 100 calls per hour
perm = rate_limited(read("mcp:github:*"), max_calls_per_hour=100)

# Full manual construction
from kavachos.types import Permission
perm = Permission(
    resource="mcp:github:*",
    actions=["read", "write"],
    constraints=PermissionConstraints(
        max_calls_per_hour=200,
        ip_allowlist=["10.0.0.0/8"],
    ),
)
```

---

## Audit log

```python
from kavachos.types import AuditFilters, ExportOptions

# Query the audit log
entries = await client.audit.query(
    AuditFilters(
        agent_id="agent-abc123",
        result="allowed",
        limit=50,
    )
)
for entry in entries:
    print(entry.timestamp, entry.action, entry.resource, entry.result)

# Paginated response (includes total count)
page = await client.audit.query_paginated(AuditFilters(limit=20, offset=0))
print(f"{len(page.entries)} of {page.total}")

# Export as JSON or CSV
csv_text = await client.audit.export(
    ExportOptions(
        format="csv",
        since="2024-01-01T00:00:00Z",
    )
)
```

---

## Delegation

Delegate a subset of an agent's permissions to another agent, with an optional
depth limit.

```python
from kavachos.types import DelegateInput
from kavachos.permissions import read

# Create a delegation
chain = await client.delegation.create(
    DelegateInput(
        from_agent="agent-abc123",
        to_agent="agent-def456",
        permissions=[read("mcp:github:repos")],
        expires_at="2025-12-31T00:00:00Z",
        max_depth=2,
    )
)

# List all chains for an agent
chains = await client.delegation.list_chains("agent-abc123")

# Get the effective (merged) permissions for an agent
perms = await client.delegation.get_effective_permissions("agent-def456")

# Revoke a delegation
await client.delegation.revoke(chain.id)
```

---

## Error handling

All exceptions inherit from `kavachos.KavachError`.

```python
from kavachos.errors import (
    KavachError,
    AuthenticationError,  # 401
    PermissionError,       # 403
    NotFoundError,         # 404
    RateLimitError,        # 429, has .retry_after
    ServerError,           # 5xx
    NetworkError,          # Transport failure
)

try:
    agent = await client.agents.get("agent-missing")
except NotFoundError:
    print("Agent does not exist")
except RateLimitError as e:
    print(f"Rate limited. Retry after {e.retry_after}s")
except AuthenticationError:
    print("Check your token")
except KavachError as e:
    print(f"[{e.code}] {e.message} (HTTP {e.status_code})")
```

---

## Configuration

```python
KavachClient(
    base_url="https://your-app.com/api/kavach",  # required
    token="kv_...",                               # optional bearer token
    headers={"X-Tenant": "acme"},                # extra headers on every request
    timeout=30.0,                                 # seconds (default 30)
)
```

---

## License

MIT
