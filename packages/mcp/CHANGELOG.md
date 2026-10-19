# @glinr/theauth-mcp

## 2.0.0

### Major Changes

- a561306: Audit API v2: explicit order, cursor paging and one event vocabulary.

  - `audit.query()` takes `order: "asc" | "desc"`. The default stays `"desc"` (newest first), so existing calls return the same order. New filters: `events`, `resource` (exact, or prefix with a trailing `*`) and `cursor`. `actions` is now applied in the query, before `limit`, instead of after it.
  - New `audit.page(filter)` returns `{ entries, nextCursor }`. The cursor is opaque and keyed on `recorded_at_ms` plus `id`, so pages are stable when rows share a millisecond or arrive between requests. `offset` is deprecated and ignored when a cursor is set.
  - New nullable `event` column (migration `0005`, index `(agent_id, event, recorded_at_ms)`) and `AuditEntry.event`. `event` says what happened (`authorize`, `policy.evaluate`, `delegation.create`, ...), `action` keeps the domain verb. Migration `0005` backfills `event` from the old action for rows it can classify and leaves the rest NULL. `event` is not part of the audit hash, like `decision_code` and `recorded_at_ms`: hash inputs are unchanged, existing chains keep verifying.
  - `GET /audit` still answers a bare array. Add `paged=true` or `cursor` for `{ entries, nextCursor }`; it also accepts `order`, `events` and `resource`. An invalid cursor answers 400.
  - The `query_audit` MCP tool gains `events`, `resource`, `order` and `cursor`, drops `offset`, and now returns `{ returned, nextCursor, entries }`.

  Upgrade notes:

  - `AuditEntry` has a new `event` field (`null` when unknown). Code that builds `AuditEntry` values by hand must set it.
  - Delegation rows now carry `action: "delegate"` with `event: "delegation.create"` or `"delegation.revoke"`. Rows written before the upgrade keep `action: "delegation.create"` or `"delegation.revoke"` (the column is hashed, so it is not rewritten); filter on `event` to see both. Anything that matched `action === "delegation.create"` must match `event` instead.
  - With `skipMigrations: true`, apply `0005` by hand (`theauth db sql --from 0005`) before deploying.

### Minor Changes

- a561306: Agent tokens now start with `ta_` instead of `kv_` (a leftover of the old kavachOS name). The format is otherwise unchanged: `ta_` plus 43 base64url characters (32 random bytes), SHA-256 hashed at rest.

  Compatible migration: tokens already issued with `kv_` keep validating. Lookups are by token hash, so no stored data is rewritten and no database migration is needed. `agent.rotate` issues a `ta_` token for a legacy agent and retires the old one. A bearer string with neither prefix is now rejected before any database lookup.

  Added `AGENT_TOKEN_PREFIX`, `LEGACY_AGENT_TOKEN_PREFIXES`, `isAgentToken` and `agentTokenLookupPrefix` to `@glinr/theauth`. The MCP `inspect_token` tool recognizes both prefixes. If you match agent tokens by prefix in your own code (proxies, log scrubbers, secret scanners), accept both `ta_` and `kv_`. "Token format" in `docs/agents.mdx` has a scanning regex for GitHub secret scanning and gitleaks.

- fe7e6c6: Input provenance end to end.

  - Content hashes in `input_provenance` are now HMAC-SHA-256 under an HKDF subkey of the audit key (version tag `hv: 2`). Old plain hashes still match. `hashInputContent(content, auditKey)` takes the key now, `hashInputContentPlain` is the old function (breaking for callers that hashed themselves, see `docs/upgrading-to-2.mdx`).
  - `audit.query({ provenance: { content } })` hashes on the server and matches keyed and plain rows. `AuditEntry.inputs` exposes the recorded sources.
  - `POST /authorize` and `POST /authorize/token` accept `inputs` or a `TheAuth-Inputs` header. `GET /audit` takes `provenanceKind`, `provenanceHash` and `provenanceContent`. `sdks/openapi.json` is regenerated.
  - Gateway reads `TheAuth-Inputs`, records it on permission checks and audit entries, and strips it before the upstream. The admin MCP server reads `_meta["io.theauth/inputs"]` and `query_audit` takes provenance filters.
  - `theauth audit query` with `--provenance <kind>[:<hash>]` and `--input-content`, and an Inputs column with chips on the dashboard audit page.
  - `policy.taint.inputLabels` (off by default) turns the kinds of `context.inputs` into `input:<kind>` call labels, so a taint rule can hold a tool such as `tool:exec` for approval after a retrieved document was in context.

## 1.2.0

### Minor Changes

- bf41bbb: Add `theauth dev` (zero-config local first run), a Cloudflare Workers template, an opt-in `adminApi` plugin with an admin MCP server (read-only by default, writes gated by approval), a black-box agent-auth conformance suite, and LangGraph and Mastra approval wrappers.

  Breaking behavior in the gateway: the client `Authorization` and `DPoP` headers are no longer forwarded to the upstream by default. Opt out with `--forward-auth` or `stripAuthHeader: false`. The gateway also gains an MCP mode, a 10 MiB request body limit, a 30 second upstream header timeout, and hop-by-hop and `X-Forwarded-*` header handling. Core gains a browser-safe `@glinr/theauth/browser` entry.

## 1.1.1

### Patch Changes

- First release on the 1.x line. The public API is the one documented in [STABILITY.md](https://github.com/glincker/theauth/blob/main/STABILITY.md) and there are no API changes from the previous 0.x release. From here breaking changes only ship in a major.

## 0.2.0

### Minor Changes

- c79f439: Add `@glinr/theauth-mcp`, a read-only stdio MCP server for inspecting a theAuth deployment from any MCP client. Tools: `check_permission` (simulator dry run), `list_agents`, `get_agent`, `query_audit`, `inspect_token` (local decode, signature not verified) and `doctor`. Configured with `THEAUTH_API_URL` and `THEAUTH_API_KEY`.
