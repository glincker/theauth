---
title: Policy Templates
description: Seven copy-paste policy templates for agent authorization covering tool allowlists, delegation scopes, org isolation, budget caps, business-hours gating, and ReBAC.
---

# Policy Templates

Seven pre-built templates for common agent authorization patterns. Each template is a self-contained directory under `docs/policies/templates/` in the repository. It contains a `policy.ts` file with the permission definitions and a `README.md` with the scenario, expected decisions, and notes on engine limitations where relevant.

Seed the exported arrays into `kavach_permissions` (and the supporting tables noted in each README), then call `engine.evaluate()` against them.

## Templates

| # | Slug | Summary |
|---|------|---------|
| 01 | tool-allowlist | One agent, only tools on an explicit allowlist can execute |
| 02 | principal-and-delegate | Principal owns read+write; delegated agent gets read-only with expiry |
| 03 | org-scoped-agents | Multi-tenant: each agent sees only its own org's resources |
| 04 | budget-gated | Hard cap on calls per hour via `maxCallsPerHour` |
| 05 | step-up-for-writes | Reads are free; writes and deletes require human approval |
| 06 | friends-of-a-friend-rebac | Document access via ReBAC graph tuples with concrete IDs |
| 07 | business-hours-only | Tool calls gated to a server-local HH:MM window |

## How to use a template

1. Copy `policy.ts` from the template directory into your project.
2. Seed the exported permission arrays into `kavach_permissions` using your database adapter.
3. For templates that need supporting rows (delegation chains, ReBAC tuples, rate-limit counters), follow the instructions in the template's `README.md`.
4. Call `engine.evaluate({ subject, action, resource })` in your request handler.

The tests under `packages/core/tests/policies/templates/` show exactly how each template behaves and can serve as integration tests in your own suite.

## Template 01: Tool allowlist

One agent with an explicit list of tools it may call. Any tool not on the list is denied.

```typescript
// policies/templates/01-tool-allowlist/policy.ts
export const permissions = [
  { resource: 'mcp:github:repos', actions: ['read'] },
  { resource: 'mcp:github:issues', actions: ['read', 'comment'] },
  { resource: 'mcp:linear:tasks', actions: ['read', 'write'] },
  // any mcp:* resource NOT listed here is denied
];
```

## Template 02: Principal and delegate

An orchestrator with read+write delegates read-only to a sub-agent with a 1-hour expiry.

```typescript
// Principal (orchestrator)
const orchestrator = await kavach.agent.create({
  ownerId: 'user-123',
  name: 'orchestrator',
  type: 'autonomous',
  permissions: [
    { resource: 'mcp:github:*', actions: ['read', 'write'] },
  ],
});

// Sub-agent (delegated)
const delegate = await kavach.agent.create({
  ownerId: 'user-123',
  name: 'delegate',
  type: 'delegated',
  permissions: [],
});

await kavach.delegate({
  fromAgent: orchestrator.id,
  toAgent: delegate.id,
  permissions: [{ resource: 'mcp:github:*', actions: ['read'] }],
  expiresAt: new Date(Date.now() + 3_600_000),
  maxDepth: 1,
});
```

## Template 05: Step-up for writes

Reads proceed automatically; writes and deletes require human approval.

```typescript
export const permissions = [
  { resource: 'mcp:*', actions: ['read'] },
  {
    resource: 'mcp:*',
    actions: ['write', 'delete'],
    constraints: { requireApproval: true },
  },
];
```

## Related pages

- [Permission Engine](permissions.md)
- [Delegation](../concepts/delegation.md)
