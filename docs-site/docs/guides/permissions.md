---
title: Permission Engine
description: Authorize agent actions via resource pattern matching and per-permission constraints including rate limits, time windows, IP allowlists, and human approval gates.
---

# Permission Engine

A permission grants an agent the right to perform one or more actions on a resource. TheAuth evaluates permissions at call time by checking whether any of the agent's permissions match the requested resource and include the requested action, then verifying all constraints pass.

| Field | Type | Description |
|---|---|---|
| `resource` | `string` | Colon-separated resource path. Wildcards (`*`) match exactly one segment. |
| `actions` | `string[]` | The actions this permission grants. No fixed set; define what fits your tools. |
| `constraints` | `PermissionConstraints` | Optional conditions that must all be satisfied for the permission to apply. |

## Resource pattern matching

Resources follow a colon-separated hierarchy. The `resource` field in a permission is matched against the resource in the authorization request using exact matches or wildcards.

```
mcp:github:repos        // exact match
mcp:github:*            // matches any direct child of mcp:github
mcp:*                   // matches anything directly under mcp
*                       // matches all resources
```

A wildcard matches exactly one segment. `mcp:github:*` matches `mcp:github:repos` and `mcp:github:issues`, but not `mcp:github:repos:comments` (that is two segments deeper).

```typescript
// This permission...
{ resource: 'mcp:github:*', actions: ['read'] }

// ...matches these:
// mcp:github:repos          yes
// mcp:github:issues         yes
// mcp:github:pull_requests  yes

// ...but NOT these:
// mcp:github                no (no wildcard segment)
// mcp:slack:channels        no (different namespace)
// mcp:github:repos:comments no (two levels deeper)
```

## Actions

Actions describe what the agent can do to a resource. TheAuth does not enforce a fixed set; you define what makes sense for your tools.

Common actions in MCP contexts:

| Action | Typical use |
|---|---|
| `read` | Fetching data, listing resources |
| `write` | Creating or modifying resources |
| `execute` | Running tools, shell commands, deployments |
| `delete` | Permanent removal of resources |

An authorization check passes when an agent has a permission with: a matching resource pattern, the requested action in that permission's `actions` array, and all constraints satisfied.

## Constraints

### Rate limiting

Limits how many times an agent can perform an action per hour using the permission:

```typescript
{
  resource: 'mcp:github:*',
  actions: ['read'],
  constraints: {
    maxCallsPerHour: 100,
  },
}
```

### Human-in-the-loop approval

Prevents automatic authorization. The call is logged and denied until a human approves it through your application's approval flow.

```typescript
{
  resource: 'mcp:deploy:production',
  actions: ['execute'],
  constraints: {
    requireApproval: true,
  },
}
```

The authorization result has `allowed: false` and reason `APPROVAL_REQUIRED`. Your application is responsible for presenting the approval UI and re-authorizing after approval.

!!! info
    TheAuth does not ship an approval UI. It provides the enforcement point. How you build the human review step is up to you.

### Time windows

Restricts when an action is allowed. Times are in 24-hour format, UTC.

```typescript
{
  resource: 'mcp:github:*',
  actions: ['read', 'write'],
  constraints: {
    timeWindow: { start: '09:00', end: '17:00' },
  },
}
```

Calls outside the window return `allowed: false`. Useful for business-hours-only policies or maintenance windows.

### IP allowlist

Restricts which source IPs can use the permission. Accepts CIDR notation.

```typescript
{
  resource: 'mcp:internal:*',
  actions: ['read', 'write', 'execute'],
  constraints: {
    ipAllowlist: ['10.0.0.0/8', '172.16.0.0/12'],
  },
}
```

Pass the caller's IP in the authorization request for this to take effect. Requests from IPs outside the list are denied.

## Permission templates

TheAuth ships named templates for common patterns. Import them from `@glinr/theauth`:

```typescript
import { permissionTemplates, getPermissionTemplate } from '@glinr/theauth';

const agent = await kavach.agent.create({
  ownerId: 'user-123',
  name: 'readonly-agent',
  type: 'autonomous',
  permissions: permissionTemplates.readonly,
});
```

Available templates:

| Template | Actions | Resource | Notes |
|---|---|---|---|
| `readonly` | `read` | `*` | |
| `readwrite` | `read`, `write` | `*` | |
| `admin` | `*` | `*` | All actions on all resources |
| `mcpBasic` | `read`, `execute` | `mcp:*` | |
| `mcpFull` | `read`, `write`, `execute` | `mcp:*` | |
| `rateLimitedRead` | `read` | `*` | 100 calls/hour |
| `approvalRequired` | `*` | `*` | Every call requires human approval |
| `businessHours` | `read`, `write`, `execute` | `*` | 09:00-17:00 UTC |

Templates are plain `Permission[]` arrays. Spread and extend them directly:

```typescript
permissions: [
  ...permissionTemplates.mcpBasic,
  { resource: 'tool:custom_tool', actions: ['execute'] },
]
```

Use `getPermissionTemplate(name)` when you need a deep copy rather than a reference to the shared array:

```typescript
const perms = getPermissionTemplate('mcpBasic');
perms[0].actions.push('write'); // safe, does not mutate the original
```

!!! warning
    Spreading directly from `permissionTemplates` gives you a reference to the original array entries. If you mutate the objects after spreading, you will modify the template. Use `getPermissionTemplate` when you need to modify entries.

## Related pages

- [Delegation](../concepts/delegation.md)
- [Policy Templates](policy-templates.md)
- [Audit Events](../reference/audit-events.md)
- [Security: Compliance](../security/compliance.md)
