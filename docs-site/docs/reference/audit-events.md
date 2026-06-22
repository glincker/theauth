---
title: Audit Events
description: Immutable logging of every authorization decision, with filtering, export, and compliance references.
---

# Audit Events

Every call to `kavach.authorize()` or `kavach.authorizeByToken()` writes an entry to the audit log, regardless of outcome. Allowed, denied, and rate-limited calls are all recorded. The log is append-only: entries are never updated or deleted.

`authorize()` returns an `auditId` linking the decision to its log entry:

```typescript
const result = await kavach.authorize(agent.id, {
  action: 'read',
  resource: 'mcp:github:repos',
});

console.log(result.auditId); // "aud_3f8a..."
```

## AuditEntry type

| Field | Type | Description |
|---|---|---|
| `id` | `string` | Unique entry identifier, prefixed `aud_`. |
| `agentId` | `string` | The agent that triggered the authorization check. |
| `userId` | `string` | The user who owns the agent. |
| `action` | `string` | The action the agent attempted (e.g. `read`, `write`, `delete`). |
| `resource` | `string` | The resource the action was attempted on. |
| `parameters` | `Record<string, unknown>` | Arguments passed to the tool at the time of the call. |
| `result` | `'allowed' \| 'denied' \| 'rate_limited'` | The outcome of the authorization check. |
| `durationMs` | `number` | Time taken to evaluate the decision, in milliseconds. |
| `tokensCost` | `number` | Optional token usage from the agent's LLM call, if provided. |
| `timestamp` | `Date` | When the authorization check occurred. |

## Querying logs

All filter fields are optional and combinable. Without filters, the query returns all entries up to the `limit`.

```typescript
const logs = await kavach.audit.query({
  agentId: 'agt_...',
  userId: 'user-123',
  result: 'denied',
  since: new Date('2025-01-01'),
  until: new Date('2025-02-01'),
  actions: ['write', 'delete'],
  limit: 100,
  offset: 0,
});
```

### Query parameters

| Parameter | Type | Description |
|---|---|---|
| `agentId` | `string` | Filter to a specific agent. |
| `userId` | `string` | Filter to all agents owned by a user. |
| `since` | `Date` | Include entries on or after this timestamp. |
| `until` | `Date` | Include entries before this timestamp. |
| `actions` | `string[]` | Filter to specific action names. |
| `result` | `string` | Filter by outcome: `'allowed'`, `'denied'`, or `'rate_limited'`. |
| `limit` | `number` | Maximum entries to return. Default is 1000. |
| `offset` | `number` | Pagination offset. |

## Exporting logs

```typescript
// JSON export
const json = await kavach.audit.export({ format: 'json' });

// CSV export, suitable for spreadsheets and compliance tools
const csv = await kavach.audit.export({ format: 'csv' });

// Export a specific time range
const q4 = await kavach.audit.export({
  format: 'csv',
  since: new Date('2024-10-01'),
  until: new Date('2025-01-01'),
});
```

## Compliance use

The audit log is the primary evidence artifact for compliance frameworks. See [Compliance Overview](../security/compliance.md) for how audit entries map to EU AI Act, NIST AI RMF, SOC 2, and ISO 42001 requirements.

Verifiable Credential export of audit entries is planned.

!!! info "SIEM streaming"
    For streaming audit events in real time to SIEM platforms, see [Webhooks and Events](../guides/webhooks-events.md). A dedicated OTLP audit sink package is planned.

## Related pages

- [Compliance Overview](../security/compliance.md)
- [Trust Scoring](../concepts/trust-scoring.md)
- [Permission Engine](../guides/permissions.md)
