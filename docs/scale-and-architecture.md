# Scale and architecture notes

Status: hypotheses. Everything below comes from reading the code on the `release/wave2-2026-10` branch, not from measurements. The benchmark harness in `benchmarks/` exists to confirm or kill each item. Until a CI run has produced numbers (see [benchmarks](./benchmarks.mdx)), treat every "expected effect" as a prediction. I have not put any timing figures in this file on purpose.

The facts (what the code does) are stated plainly. The predictions are marked **Hypothesis**.

## How to read this

Each section has the same shape: what the code does today, why it might matter at scale, a concrete recommendation, and the effect we expect. The benchmark scenario that should test it is named at the end, so a CI run can settle it.

## 1. Audit hash chain: head read, insert, retry

Code: `packages/core/src/audit/chain.ts`.

With `audit.tamperEvident` on, every audit row is appended in two sequential database calls: read the agent's chain head (`ORDER BY chain_seq DESC LIMIT 1` on `(agent_id, chain_seq)`), compute the hash, then insert. Writers for the same agent inside one process are queued behind each other through a per-agent promise chain. Across processes there is no queue. A second writer that picked the same sequence number hits the unique index, sleeps for a random time of up to `4 * (attempt + 1)` ms, re-reads the head and tries again, up to 30 attempts.

Consequences we can read off the code:

- Same-agent throughput in one process is bounded by two round trips per row, in series. On a database with real network latency that is the dominant cost.
- With N instances writing the same agent, each successful append can cost up to N-1 wasted read+insert attempts. Work grows faster than the number of writers.
- Different agents never contend, which is what the per-agent chain design intends.
- `authorize()` awaits the audit write before it returns, so the chain cost is added to the caller's latency.

**Recommendation A (cache the head):** keep the last `(seq, hash)` per agent in process, and only fall back to the head read after a unique violation. **Hypothesis:** removes one of the two round trips in the common single-instance case, so same-agent append latency drops noticeably on Postgres and MySQL and barely changes on in-memory SQLite.

**Recommendation B (batch per agent):** let the queue drain several pending rows for one agent into a single multi-row insert with consecutive sequence numbers. **Hypothesis:** same-agent throughput under many concurrent writers goes up because the round trips are shared. Latency for a lone writer does not change.

**Recommendation C (take audit off the request path):** an opt-in mode where `authorize()` enqueues the row and returns, with a bounded queue and a flush on shutdown. **Hypothesis:** `authorize()` p50 and p99 fall to roughly the cost of the decision alone. The price is a window where a crash can lose rows, so this must stay opt-in and documented.

**Recommendation D (multi-instance deployments):** on Postgres, take a per-agent advisory lock around the append so racing instances queue in the database instead of retrying. **Hypothesis:** removes wasted attempts and flattens p99 for the multi-instance case.

Benchmark scenarios: `audit append` (all variants), especially the multi-instance rows on Postgres and MySQL.

## 2. In-process rate limit and replay state

Code: `packages/core/src/auth/rate-limiter.ts`, `auth/stores/memory.ts`, `auth/rate-limit.ts`, `mcp/dpop.ts`, `policy/abac.ts`.

Three different mechanisms hold counters or replay state, and they differ in where that state lives:

- `createRateLimiter` keeps a `Map` of timestamp arrays in process memory. One array entry per allowed hit inside the window.
- The `rateLimit` plugin uses `MemoryStore` (a fixed window counter in a `Map`) unless a store or `secondaryStorage` is configured. Memory is the default.
- The DPoP `jti` replay cache falls back to per-context memory unless `dpop.storage` is set.
- The `maxCallsPerHour` permission constraint stores its counter in the database (`theauth_rate_limits`, 5 minute windows). It reads all rows for the agent and resource from the last hour, then updates or inserts. That is a read followed by a write of `count + 1`, not an atomic increment.

Consequences:

- With two or more instances behind a load balancer, memory-backed limits are per instance. The effective limit is the configured limit times the instance count, and a DPoP proof replayed against a different instance is not detected. `secondaryStorage` (Redis, KV, database) exists to fix this, but nothing forces you to configure it.
- The sliding window array grows with the allowed hit count per key, so a high limit on a hot key means long arrays that are sliced on every call.
- Two concurrent calls can both read `count = 7` and both write `8`, so the database counter can undercount and let more calls through than the limit.

**Recommendation A:** log a one-time warning at startup when `NODE_ENV=production` and rate limit or DPoP state is memory-backed. **Hypothesis:** no performance change, but it moves a silent correctness gap into view. (Docs already cover this in [choose storage](/choose-storage).)

**Recommendation B:** replace the read-then-write in the `maxCallsPerHour` check with an atomic upsert (`count = count + 1`) or a `secondaryStorage` counter. **Hypothesis:** removes the lost-update window and one query per call; for the DB path the check becomes a single statement.

**Recommendation C:** use a fixed-window or sliding-window-counter algorithm for `createRateLimiter` instead of a timestamp array. **Hypothesis:** memory per key becomes constant and the per-call cost stops depending on the limit.

Benchmark scenarios: `rate-limit check` (in-process rows and the DB counter row).

## 3. Database lookups on every authorize

Code: `packages/core/src/theauth.ts` (`authorize`), `agent/agent.ts`, `permission/engine.ts`, `delegation/delegation.ts`.

`authorize(agentId, request)` does, in order:

1. `agent.get`: one query on `theauth_agents` by primary key, then one on `theauth_permissions` by `agent_id`.
2. The permission check itself, in memory.
3. If the check denies: `getEffectivePermissions`, one query on `theauth_delegation_chains` by `to_agent_id` and status, then a second in-memory check.
4. An audit insert when `auditAll` is on (plus the chain head read when the chain is on).

So an allowed call with auditing costs three queries (four with the chain), and a denied call that has inbound delegations costs more. Also: the permission engine writes an audit row when the agent's own permissions deny, even if the delegated pass then allows. A call that succeeds through delegation can therefore leave a denied row and an allowed row. That is a behavior question for the owner as much as a performance one.

The newer policy engine (`policy/engine.ts`) has a cache, but the comment in `permission/engine.ts` says `authorize` still evaluates direct permissions itself, so that cache is not on this path today.

`agent.validateToken` (the token path) runs a lookup by `token_hash`, then an `UPDATE` of `last_active_at` on every successful validation, then a permissions query. A read path that always writes.

**Recommendation A:** a short-TTL in-process cache of `AgentIdentity` plus delegated permissions, invalidated on `update`, `revoke`, `rotate` and `delegation.revoke` in the same process. **Hypothesis:** removes two or three queries per authorize on the hot path. Cross-instance invalidation is the cost: a revoke on one instance is seen by others only after the TTL. That is a security tradeoff and the TTL has to be small and configurable.

**Recommendation B:** fetch agent and permissions in one joined query. **Hypothesis:** saves one round trip per call without any staleness risk. Smaller win than A, no tradeoff.

**Recommendation C:** only write `last_active_at` when the stored value is older than a threshold (for example 60 seconds). **Hypothesis:** turns most token validations into read-only calls.

**Recommendation D:** in the delegated pass, skip the second audit write, or mark it, so one request produces one row. **Hypothesis:** halves audit volume for delegated calls.

Benchmark scenarios: `authorize` (all variants), `token verify`.

## 4. Delegation chains: queries and depth

Code: `packages/core/src/delegation/delegation.ts`.

Permissions are copied onto each chain row when the delegation is created, and `getEffectivePermissions` only reads rows where the agent is the target. That means chain depth does not add queries at authorize time. An agent at depth 3 costs the same single delegation query as an agent at depth 1. The benchmark has depth 1, 2 and 3 rows so this can be confirmed.

Where depth does cost something:

- `delegate()` reads the parent's own permissions and its inbound chains to check the subset rule, and may re-read inbound chains after the insert to catch a concurrent revoke.
- `revokeDelegation` recurses: for each child chain it issues a query, an update and another child query, one after the other. Revoking the root of a wide tree is N+1 shaped.
- The queries filter on `to_agent_id` (authorize) and `from_agent_id` (revoke, list), and neither column has an index.

**Recommendation A:** add indexes on `(to_agent_id, status)` and `(from_agent_id, status)`. **Hypothesis:** no effect on small SQLite tables, a clear effect on Postgres and MySQL once the chain table has many rows, because the filters stop scanning.

**Recommendation B:** make revoke iterative with one query per tree level (`WHERE from_agent_id IN (...)`) and one batched update. **Hypothesis:** revoke time stops growing with the number of descendants.

Benchmark scenarios: `authorize` rows for delegation depth 1, 2, 3, and `simulate` for the same depths.

## 5. Session lookup

Code: `packages/core/src/session/session.ts`.

`validate(token)` verifies the JWT (no I/O), then selects the session row by primary key. An expired row is deleted on the way out. `create` is one insert. This is a single indexed query per request, which is about as cheap as a database-backed session gets. By contrast `jwt verifySession` (access tokens from the JWT session module) does no database work at all, at the price that an access token cannot be revoked before it expires.

Where it can hurt: `list(userId)` and `revokeAll(userId)` filter on `user_id`, which has no index, and nothing in the schema removes expired rows except the opportunistic delete in `validate`.

**Recommendation A:** index `theauth_sessions(user_id)` and `(expires_at)`, and document a periodic cleanup of expired rows. **Hypothesis:** `list` and `revokeAll` stop scanning the whole table; the hot `validate` path is unchanged.

**Recommendation B:** where per-request revocation is not needed, use the cookie cache (`session/cookie-cache.ts`) or the stateless JWT access token to skip the row lookup. **Hypothesis:** removes the one query from the hot path; the benchmark's `token verify` rows show the size of the gap per backend.

Benchmark scenarios: `session`, `token verify`.

## 6. Missing indexes

`packages/core/src/db/migrations.ts` creates indexes for the audit chain, a few feature tables (login history, cost events, ReBAC, refresh tokens) and unique columns. The core tables below have only their primary keys. Postgres and MySQL do not index foreign keys automatically, and SQLite does not either.

| Table | Column(s) queried | Where | Proposed index |
| --- | --- | --- | --- |
| `theauth_agents` | `token_hash` | `validateToken` | unique on `token_hash` |
| `theauth_agents` | `owner_id`, `status` | `create` (max per user check), `list` | `(owner_id, status)` |
| `theauth_permissions` | `agent_id` | `get`, `validateToken` | `(agent_id)` |
| `theauth_delegation_chains` | `to_agent_id`, `status` | `getEffectivePermissions` | `(to_agent_id, status)` |
| `theauth_delegation_chains` | `from_agent_id`, `status` | `revokeDelegation`, `listChains` | `(from_agent_id, status)` |
| `theauth_audit_logs` | `timestamp` | `audit.query` (ordered by it), `cleanup` | `(timestamp)` and `(agent_id, timestamp)` |
| `theauth_rate_limits` | `agent_id`, `resource`, `window_start` | `maxCallsPerHour` check | `(agent_id, resource, window_start)` |
| `theauth_sessions` | `user_id` | `list`, `revokeAll` | `(user_id)` |

`(agent_id, chain_seq)` on the audit table already serves any query that filters on `agent_id` alone, because `agent_id` is its leading column.

**Hypothesis:** on small SQLite databases none of these show up. On Postgres and MySQL they matter as the tables grow, and the token lookup (a full scan per request without the unique index) is the one most likely to be visible first. The harness does not grow tables to production sizes in one run, so confirming this needs a seeded run with a large row count. That is a follow-up, not something the current scenarios prove.

New indexes ship as migrations with `CREATE INDEX IF NOT EXISTS`, and MySQL needs the same special handling the chain index already has (no `IF NOT EXISTS`, key prefix length on text columns).

## 7. Two smaller findings

- **sql.js file mode rewrites the whole file.** For the `sqlite` provider with a file path, `database.ts` wraps `run` and exports the entire database to disk after every `INSERT`, `UPDATE`, `DELETE` or DDL statement. Per-write cost therefore grows with database size. **Recommendation:** point file-backed deployments at `sqlite-native` (better-sqlite3), and say so in the database docs. **Hypothesis:** write latency on file databases stops depending on file size. The benchmark has file and in-memory rows for both SQLite providers.
- **`agent.create` reads every active agent the owner has** to enforce `maxPerUser`, then compares the length. **Recommendation:** use `SELECT count(*)`. **Hypothesis:** removes the growth in create latency for owners with many agents. The `createAgent` rows (single owner versus fresh owner) are built to show this.

## What would change these notes

Run the `Benchmarks` workflow (manual trigger) and read the generated report. If a hypothesis above is wrong, delete it. If a recommendation holds, the number from the report goes next to it and it becomes a ticket.
