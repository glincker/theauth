---
title: Agent Identity
description: Issue, rotate, revoke, and audit AgentIdentity tokens. Scoped permissions, parent/child delegation, and per-agent rate limits in one API.
---

# Agent Identity

An `AgentIdentity` is the primary entity in TheAuth. It represents one AI agent, a process acting on behalf of a human user. Agents are not users. No password, no session, no OAuth flow. Just a token, a set of permissions, and an audit row for every call.

Create one against an existing user ID, hand the token to the agent, and check every action through `authorize()`.

```ts
const agent = await kavach.agent.create({
  ownerId: user.id,
  name: 'code-reviewer',
  type: 'autonomous',
  permissions: [
    { resource: 'mcp:github:*', actions: ['read'] },
  ],
});

// agent.token is a kv_... bearer, shown once, hashed at rest
console.log(agent.token);
```

## Agent fields

| Field | Type | Description |
|---|---|---|
| `id` | `string` | Stable identifier with an `agt_` prefix. Never changes. |
| `token` | `string` | Bearer token with a `kv_` prefix. Shown once at creation, then SHA-256 hashed. Rotate to replace. |
| `permissions` | `Permission[]` | What this agent is allowed to do. Evaluated at every `authorize()` call. |
| `status` | `'active' \| 'revoked' \| 'expired'` | Current state. Revocation is permanent. |
| `ownerId` | `string` | The user ID from your auth provider who owns this agent. |
| `name` | `string` | Human-readable label. |
| `type` | `'autonomous' \| 'delegated' \| 'service'` | Determines how the agent acquires and uses permissions. |
| `expiresAt` | `Date \| undefined` | Optional expiry. After this time, `status` becomes `expired`. |
| `metadata` | `Record<string, unknown>` | Arbitrary key/value pairs for your own use. |

## Agent types

**`autonomous`** acts independently without requiring human approval on each call, unless a permission constraint mandates it. The standard type for background agents, cron jobs, and AI assistants that run unattended.

**`delegated`** receives permissions from another agent via a delegation chain rather than having them declared at creation. Use this for ephemeral sub-agents spun up to complete one task, then discarded.

**`service`** is a long-lived identity for infrastructure, such as an MCP server or an internal microservice that calls other services on behalf of users. Treat it like a service account.

## Lifecycle

### 1. Create

```ts
const agent = await kavach.agent.create({
  ownerId: 'user-123',
  name: 'github-reader',
  type: 'autonomous',
  permissions: [
    { resource: 'mcp:github:*', actions: ['read'] },
  ],
  expiresAt: new Date(Date.now() + 7 * 24 * 3_600_000), // optional
  metadata: { purpose: 'nightly PR review' },
});

console.log(agent.token); // kv_a3f8c2e1..., only shown here
```

!!! warning
    The token is returned once at creation. TheAuth stores only the SHA-256 hash, so the plaintext cannot be recovered later. Save it immediately or rotate to get a new one.

### 2. Authenticate

Tokens use the `kv_` prefix followed by 32 random bytes as 64 hex chars. Pass as a Bearer credential:

```http
Authorization: Bearer kv_a3f8c2e1d4b5...
```

!!! tip
    Hash-only storage: a full database dump cannot reveal an active token. There are no secrets to rotate after a DB breach, only the tokens themselves.

### 3. Authorize

When a caller only has the raw token, use `authorizeByToken` in your HTTP middleware:

```ts
const token = request.headers.get('Authorization')?.replace('Bearer ', '');
if (!token) return new Response('Unauthorized', { status: 401 });

const result = await kavach.authorizeByToken(token, {
  action: 'read',
  resource: 'mcp:github:repos',
});

if (!result.allowed) {
  return new Response(result.reason ?? 'Forbidden', { status: 403 });
}
```

One database lookup (hash compare), then in-memory permission evaluation. No JWTs, no network round-trip.

### 4. Rotate

Rotation issues a new token and immediately invalidates the old one. Atomic: no window where both are valid.

```ts
const rotated = await kavach.agent.rotate(agentId);
// rotated.token is the new plaintext token
```

Rotate on a schedule, or any time you suspect a token has been exposed.

### 5. Update or list

Permission updates take effect immediately. In-flight requests that already passed authorization are not affected.

```ts
await kavach.agent.update(agentId, {
  name: 'github-reader-v2',
  permissions: [{ resource: 'mcp:github:*', actions: ['read', 'comment'] }],
});

const active = await kavach.agent.list({
  userId: 'user-123',
  status: 'active',
  type: 'autonomous',
});
```

### 6. Revoke

```ts
await kavach.agent.revoke(agentId);
// All future authorize() calls return allowed: false
// The agent's token is rejected immediately
```

!!! warning
    Revocation is permanent. There is no un-revoke. To restore access, create a new agent.

## Agent limits

The default is 10 active agents per user. Raise at initialization:

```ts
const kavach = createAuth({
  database: { provider: 'sqlite', url: 'kavach.db' },
  agents: {
    maxPerUser: 50,
  },
});
```

Attempts to exceed the cap return an error with code `AGENT_LIMIT_EXCEEDED`.

## What agents are not

An agent is not a user. It has no email, no password, no session, no OAuth account. It has a bearer token and a permission set. If you find yourself reaching for password reset, email verification, or social sign-in on an agent, you want a user, not an agent. Create the user first, then create agents that the user owns.

## Related pages

- [Permission Engine](../guides/permissions.md)
- [Delegation](delegation.md)
- [Sessions](sessions.md)
- [Audit Events](../reference/audit-events.md)
