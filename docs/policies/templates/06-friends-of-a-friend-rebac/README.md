# Template 06, ReBAC document sharing

Document access is decided by the relationship graph, not a static list of agent IDs. A permission row carries a `relation` field ("viewer"). The engine asks the ReBAC bridge whether the requesting agent holds that relation on the specific document. Add or remove tuples in `kavach_rebac_relationships` to grant or revoke access without touching permission rows.

## Input shape

```ts
engine.evaluate({
  subject: { agentId: "agent-xyz" },
  action: "read",
  resource: "doc:42",   // must be a concrete ID
});
```

## Example decisions

| Agent | Tuple exists? | Decision |
|---|---|---|
| agent-xyz | yes (`viewer` on `doc:42`) | **allow** |
| agent-abc | no | **deny** |
| any agent | resource = `doc:*` | **deny**, wildcard rejected |

## Engine limitation

The ReBAC bridge rejects wildcard resource IDs. A resource string containing `*` immediately returns `matched=false` with reason `rebac:wildcard-resource-not-supported`. Always use concrete identifiers (`doc:42`, `doc:abc-123`) in permission rows that carry a `relation` field. If you need to grant access to all documents for an agent, insert one tuple per document or use a parent resource with an inherited relation.

## Tweak this

- Add an `editor` relation tuple to grant write access alongside `viewer`.
- Use `rebac.expand()` to list all documents a given agent can view without running N individual checks.
