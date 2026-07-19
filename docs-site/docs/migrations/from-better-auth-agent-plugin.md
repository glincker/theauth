---
title: From better-auth agent plugin
description: Switch from @better-auth/agent-auth to TheAuth AgentIdentity. Maps scopes to Permission objects and delegation chains, with cascading revocation support.
---

# From better-auth agent plugin

`@better-auth/agent-auth` is better-auth's attempt to add AI-agent support alongside a human-first auth library. It is marked "heavy development, not yet stable" in their repo as of 2026-03. Moving to TheAuth gives you a single codebase where agents are a first-class entity instead of a separate package bolted onto the user model.

Both libraries share the same ancestor on the human-auth side. Most of the familiar hooks keep their names. The agent story is the part that changes materially.

If you use the human-auth half of better-auth and not the agent plugin yet, read the [general better-auth migration guide](from-better-auth.md) first. This page only covers the agent-plugin deltas.

## Where the model diverges

better-auth treats an agent as an OAuth client attached to a user. A single-hop delegation is possible. There is no delegation chain tracking, no trust score, no cost attribution, no ephemeral session type, and no MCP OAuth 2.1 authorization server built in.

TheAuth treats an agent as a primary database entity with its own lifecycle:

- `AgentIdentity` row in the schema, owned by a user, with status transitions (`active`, `revoked`, `expired`)
- Multi-hop delegation chains with depth limits and cascading revocation
- Trust scoring, 5 levels, computed from the audit log
- Cost attribution per agent, tool, and chain
- MCP OAuth 2.1 authorization server baked into the same instance
- Ephemeral agent sessions for one-off tasks

## Concepts map

| `@better-auth/agent-auth` | TheAuth |
|---|---|
| `agentPlugin()` added to `betterAuth` | Built into `createTheAuth`. No plugin needed for the core agent surface. |
| `auth.api.createAgent({ userId, scopes })` | `kavach.agent.create({ ownerId, name, type, permissions })` |
| `agent.accessToken` | `agent.token` (prefix `kv_`, returned once, SHA-256 hashed at rest) |
| `agent.scopes: string[]` | `agent.permissions: Permission[]` (resource patterns + actions + constraints) |
| `agent.kind: 'service' \| 'user-agent'` | `agent.type: 'autonomous' \| 'delegated' \| 'service'` |
| `auth.api.verifyAgentToken(token)` | `kavach.agent.verifyToken(token)` or `kavach.authorizeByToken(token, req)` |
| Single-hop delegation via second `createAgent` call | `kavach.delegation.create({ fromAgent, toAgent, permissions, maxDepth })` |
| No cascading revocation | Revoking a parent cascades down the chain. Immediate. |
| No audit module (relies on generic logs) | `kavach.audit.query()` + structured CSV and JSON export |
| No trust score | `kavach.trust.computeScore(agentId)` |
| No MCP server | Built-in OAuth 2.1 authorization server, PKCE S256, RFC 9728 / 8707 / 8414 / 7591 |
| No per-agent rate cap | Permission constraint: `maxCallsPerHour` |
| No approval gate | Permission constraint: `requireApproval: true`, surfaces a CIBA-style approval flow |
| No ephemeral sessions | `kavach.ephemeral.create({ agentId, ttlMs })` |

## Server setup

=== "Before (better-auth + agent plugin)"
    ```ts
    // lib/auth.ts
    import { betterAuth } from 'better-auth';
    import { agent } from '@better-auth/agent-auth';

    export const auth = betterAuth({
      database: { provider: 'postgresql', url: process.env.DATABASE_URL },
      emailAndPassword: { enabled: true },
      plugins: [agent()],
    });
    ```
=== "After (TheAuth)"
    ```ts
    // lib/kavach.ts
    import { createTheAuth } from '@glinr/theauth';
    import { emailPassword } from '@glinr/theauth/auth';

    export const kavach = createTheAuth({
      database: { provider: 'postgres', url: process.env.DATABASE_URL! },
      secret: process.env.KAVACH_SECRET!,
      baseUrl: process.env.AUTH_BASE_URL!,
      agents: { enabled: true, auditAll: true },
      plugins: [emailPassword()],
    });
    ```

## Scopes to permissions

The better-auth agent plugin uses flat string scopes (`['read:files', 'write:db']`). TheAuth uses structured Permission objects with resource patterns, action arrays, and optional constraints.

=== "Before (scopes)"
    ```ts
    const agent = await auth.api.createAgent({
      userId: 'user-123',
      scopes: ['read:github', 'write:linear'],
    });
    ```
=== "After (permissions)"
    ```ts
    const agent = await kavach.agent.create({
      ownerId: 'user-123',
      name: 'my-agent',
      type: 'autonomous',
      permissions: [
        { resource: 'mcp:github:*', actions: ['read'] },
        { resource: 'mcp:linear:*', actions: ['read', 'write'] },
      ],
    });
    ```

## Delegation chains

=== "Before (single-hop, no chain tracking)"
    ```ts
    // Creates a second agent with a subset of the first agent's scopes
    const delegate = await auth.api.createAgent({
      userId: 'user-123',
      scopes: ['read:github'],
      parentAgentId: agent.id,
    });
    ```
=== "After (tracked chains with cascading revocation)"
    ```ts
    const delegate = await kavach.agent.create({
      ownerId: 'user-123',
      name: 'delegate',
      type: 'delegated',
      permissions: [],
    });

    const chain = await kavach.delegate({
      fromAgent: agent.id,
      toAgent: delegate.id,
      permissions: [{ resource: 'mcp:github:*', actions: ['read'] }],
      expiresAt: new Date(Date.now() + 3_600_000),
      maxDepth: 1,
    });

    // Revoking agent also revokes delegate
    await kavach.agent.revoke(agent.id);
    ```

## Related pages

- [From better-auth](from-better-auth.md)
- [Agent Identity](../concepts/agents.md)
- [Delegation](../concepts/delegation.md)
