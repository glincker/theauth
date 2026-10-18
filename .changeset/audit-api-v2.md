---
"@glinr/theauth": major
"@glinr/theauth-mcp": major
---

Audit API v2: explicit order, cursor paging and one event vocabulary.

- `audit.query()` takes `order: "asc" | "desc"`. The default stays `"desc"` (newest first), so existing calls return the same order. New filters: `events`, `resource` (exact, or prefix with a trailing `*`) and `cursor`. `actions` is now applied in the query, before `limit`, instead of after it.
- New `audit.page(filter)` returns `{ entries, nextCursor }`. The cursor is opaque and keyed on `recorded_at_ms` plus `id`, so pages are stable when rows share a millisecond or arrive between requests. `offset` is deprecated and ignored when a cursor is set.
- New nullable `event` column (migration `0005`, index `(agent_id, event, recorded_at_ms)`) and `AuditEntry.event`. `event` says what happened (`authorize`, `policy.evaluate`, `delegation.create`, ...), `action` keeps the domain verb. Migration `0005` backfills `event` from the old action for rows it can classify and leaves the rest NULL. `event` is not part of the audit hash, like `decision_code` and `recorded_at_ms`: hash inputs are unchanged, existing chains and the Go verifier keep verifying.
- `GET /audit` still answers a bare array. Add `paged=true` or `cursor` for `{ entries, nextCursor }`; it also accepts `order`, `events` and `resource`. An invalid cursor answers 400.
- The `query_audit` MCP tool gains `events`, `resource`, `order` and `cursor`, drops `offset`, and now returns `{ returned, nextCursor, entries }`.

Upgrade notes:

- `AuditEntry` has a new `event` field (`null` when unknown). Code that builds `AuditEntry` values by hand must set it.
- Delegation rows now carry `action: "delegate"` with `event: "delegation.create"` or `"delegation.revoke"`. Rows written before the upgrade keep `action: "delegation.create"` or `"delegation.revoke"` (the column is hashed, so it is not rewritten); filter on `event` to see both. Anything that matched `action === "delegation.create"` must match `event` instead.
- With `skipMigrations: true`, apply `0005` by hand (`theauth db sql --from 0005`) before deploying.
