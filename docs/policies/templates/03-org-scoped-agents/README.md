# Template 03, Org-scoped agents

In a multi-tenant deployment every agent's permissions are namespaced to its own org. The resource pattern `org:<slug>:*` means the agent can read and write anything inside that org but nothing outside it. Two agents from different orgs may request the same logical resource name (e.g. `org:acme:invoices` vs `org:globex:invoices`) and each is evaluated against its own scope.

## Input shape

```ts
engine.evaluate({
  subject: { agentId: "acme-bot", orgId: "acme" },
  action: "read",
  resource: "org:acme:invoices",
});
```

## Example decisions

| Agent | Resource | Decision |
|---|---|---|
| acme-bot | `org:acme:invoices` | **allow**, pattern matches |
| acme-bot | `org:acme` | **allow**, `*` also matches zero remaining segments |
| acme-bot | `org:acme:invoices:2026:q1` | **allow**, `*` matches all remaining segments |
| acme-bot | `org:acmecorp:invoices` | **deny**, segments are compared whole, so `acmecorp` is not `acme` |
| acme-bot | `org:globex:invoices` | **deny**, wrong org prefix |
| globex-bot | `org:globex:invoices` | **allow**, pattern matches |

## Tweak this

- Narrow to `org:<slug>:documents` to restrict the wildcard to one sub-category.
- Isolation comes entirely from the resource pattern on the agent's own permission rows. `subject.orgId` does not restrict an agent's direct permissions; it only scopes role lookups for user subjects and is part of the cache key.
- A `*` segment matches the rest of the path from that position, including zero segments. Never grant `*` or `org:*` to a tenant agent.
