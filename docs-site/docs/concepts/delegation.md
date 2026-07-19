---
title: Delegation
description: Grant a subset of permissions from one agent to another, with depth limits and cascading revocation.
---

# Delegation

A delegation chain lets one agent grant a subset of its permissions to another. The delegating agent keeps its own permissions unchanged. The receiving agent gains access only to what was explicitly delegated.

This pattern is most useful when an orchestrator spins up sub-agents for specific tasks. Each sub-agent gets only the access it needs, for only as long as it needs it.

!!! info
    The delegating agent must currently hold every permission it is trying to delegate. Attempting to delegate a permission not in the agent's own set fails with `INSUFFICIENT_PERMISSIONS`.

## Creating a delegation

```typescript
const chain = await kavach.delegate({
  fromAgent: orchestrator.id,
  toAgent: subAgent.id,
  permissions: [
    { resource: 'mcp:github:issues', actions: ['read'] },
  ],
  expiresAt: new Date(Date.now() + 3_600_000), // 1 hour
  maxDepth: 2,
});

console.log(chain.id);        // dlg_...
console.log(chain.depth);     // 1
console.log(chain.expiresAt); // Date
```

| Parameter | Type | Description |
|---|---|---|
| `fromAgent` | `string` | Agent ID granting the permissions. Must hold every permission being delegated. |
| `toAgent` | `string` | Agent ID receiving the permissions. |
| `permissions` | `Permission[]` | Subset of permissions to delegate. Must not exceed the `fromAgent`'s own permissions. |
| `expiresAt` | `Date` | When the delegation expires. After this point, the chain is no longer valid. |
| `maxDepth` | `number` | How many additional hops the chain can be re-delegated. Default is 3. |

## Permission subset enforcement

The permissions you delegate must be a subset of what the `fromAgent` holds. Narrower resources and fewer actions are allowed. Wider resources or new actions are rejected.

Given an orchestrator with:

```typescript
{ resource: 'mcp:github:*', actions: ['read', 'write', 'comment'] }
```

Valid delegations:

```typescript
{ resource: 'mcp:github:issues', actions: ['read'] }           // narrower resource, fewer actions
{ resource: 'mcp:github:*', actions: ['read'] }                // same resource, fewer actions
{ resource: 'mcp:github:repos', actions: ['read', 'comment'] } // narrower resource, same actions
```

Invalid delegations (rejected):

```typescript
{ resource: 'mcp:*', actions: ['read'] }                       // wider resource
{ resource: 'mcp:github:*', actions: ['read', 'delete'] }      // new action not held
```

## Revoking a delegation

```typescript
await kavach.delegation.revoke(chain.id);
// Immediate effect: subAgent.authorize() returns allowed: false
```

Revocation cascades. If the chain is `orchestrator -> sub -> subSub`, revoking `orchestrator -> sub` also revokes `sub -> subSub` immediately. Any agent that relied on the revoked permissions will get `allowed: false` on its next authorization check.

!!! warning
    Revocation takes effect on the next `authorize()` call. It does not terminate any in-progress operations.

## Effective permissions

To see the full set of permissions an agent has at a given moment, including those received through active chains:

```typescript
const effective = await kavach.delegation.getEffectivePermissions(subAgent.id);
// Returns Permission[] combining own permissions and all active delegations
```

The authorization engine calls this internally on every `authorize()` request. You can call it directly to inspect what an agent can currently do before attempting an action.

## Listing chains

```typescript
// All chains where subAgent is the receiver
const incoming = await kavach.delegation.listChains({ toAgent: subAgent.id });

// All chains originating from the orchestrator
const outbound = await kavach.delegation.listChains({ fromAgent: orchestrator.id });
```

## DelegationChain type

| Field | Type | Description |
|---|---|---|
| `id` | `string` | Unique chain identifier, prefixed `dlg_`. |
| `fromAgent` | `string` | Agent ID that created the delegation. |
| `toAgent` | `string` | Agent ID that received the delegation. |
| `permissions` | `Permission[]` | The permissions granted by this chain. |
| `expiresAt` | `Date` | Expiry time for the chain. |
| `depth` | `number` | Current depth of this chain in the delegation tree. |
| `createdAt` | `Date` | When the chain was created. |

## Typical pattern

An orchestrator holds broad permissions, plans a task, and issues short-lived narrow delegations to sub-agents.

**Step 1.** Create the orchestrator with the full permission set it needs.

```typescript
const orchestrator = await kavach.agent.create({
  ownerId: 'user-123',
  name: 'planner',
  type: 'autonomous',
  permissions: [
    { resource: 'mcp:github:*', actions: ['read', 'write', 'comment'] },
    { resource: 'mcp:linear:*', actions: ['read', 'write'] },
  ],
});
```

**Step 2.** Create the sub-agent with no direct permissions.

```typescript
const codeReviewer = await kavach.agent.create({
  ownerId: 'user-123',
  name: 'code-reviewer',
  type: 'delegated',
  permissions: [],
});
```

**Step 3.** Delegate only what the sub-agent needs, with a short expiry and `maxDepth: 1` to prevent further delegation.

```typescript
await kavach.delegate({
  fromAgent: orchestrator.id,
  toAgent: codeReviewer.id,
  permissions: [
    { resource: 'mcp:github:pulls', actions: ['read', 'comment'] },
  ],
  expiresAt: new Date(Date.now() + 30 * 60_000), // 30 minutes
  maxDepth: 1,
});
```

## Related pages

- [Agent Identity](agents.md)
- [Audit Events](../reference/audit-events.md)
- [MCP Authorization](mcp-authorization.md)
