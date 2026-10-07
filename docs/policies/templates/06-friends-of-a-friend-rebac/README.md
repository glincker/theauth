# Template 06, ReBAC document sharing

Document access is decided by the relationship graph, not a static list of agent IDs. A permission row carries a `relation` field ("viewer"). The engine asks the ReBAC bridge whether the requesting agent holds that relation on the specific document. Add or remove tuples in `theauth_rebac_relationships` to grant or revoke access without touching permission rows.

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
| agent-xyz | `viewer` tuple exists, action `write` | **deny**, the permission row only lists `read` |

## Engine limitation

The ReBAC bridge rejects wildcard resource IDs. A resource string containing `*` immediately returns `matched=false` with reason `rebac:wildcard-resource-not-supported`. Always use concrete identifiers (`doc:42`, `doc:abc-123`) in permission rows that carry a `relation` field. If you need to grant access to all documents for an agent, insert one tuple per document or register the documents under a parent resource (see below).

The policy engine builds its ReBAC module with the default rules only. Relation implication (for example `editor` implies `viewer`) and parent inheritance come from those defaults, and they exist only for the resource types `org`, `workspace`, `project`, `document`, and `resource`. A type such as `doc` has no default rules, so only a direct tuple grants access and no parent inheritance happens. Use `document` as the type if you want `editor` and `owner` tuples to imply `viewer` and parent resources to be honoured; the parent link needs a row in `theauth_rebac_resources` with `parentId` and `parentType`. For a direct tuple alone, no resource row is required.

## Tweak this

- Add an `editor` relation tuple to grant write access alongside `viewer`.
- Use the ReBAC module's `listObjects()` to list all documents a given agent can view without running N individual checks. (`expand()` returns the raw relationships where an entity is subject or object, not the objects it can access.)
