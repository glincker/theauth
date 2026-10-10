# TheAuth demo worker

A single page, backed by a Cloudflare Worker and a D1 database, that walks a visitor through the part of TheAuth people ask about first: an agent gets an identity, is allowed one thing, denied another, and stops working the moment it is revoked.

Nothing in this folder is deployed. The deploy steps below are for the project owner.

## What it shows

1. Create an agent with a name and one of two permission presets (reader or editor).
2. See the agent token once. The server keeps only a SHA-256 hash, so it cannot show it again.
3. Ask whether the agent may do something. The answer (allowed or denied) comes from `auth.authorize()` with the reason.
4. Read the audit log: agent id, action, resource, result and time.
5. Revoke the agent, send the same request again, and see it denied.

The API routes call `@glinr/theauth` core directly (`createTheAuth`, `auth.agent.create`, `auth.authorize`, `auth.audit.query`, `auth.agent.revoke`). There is no framework adapter. Hono is only the router.

| Route | Purpose |
| --- | --- |
| `GET /` | The page |
| `GET /api/info` | Limits and presets |
| `POST /api/agents` | Create an agent, returns the token once |
| `POST /api/authorize` | Check one action on one resource |
| `GET /api/audit?agentId=` | Audit rows for one agent |
| `POST /api/agents/:id/revoke` | Revoke an agent |
| `GET /healthz` | Liveness |

## Abuse limits

A public sandbox gets abused, so the demo is built to be cheap to keep up and boring to attack. All limits are environment variables (see `wrangler.toml`).

| Control | Default | Variable |
| --- | --- | --- |
| API requests per client per minute | 30 | `DEMO_REQUESTS_PER_MINUTE` |
| Agents one client may hold | 3 | `DEMO_MAX_AGENTS_PER_CLIENT` |
| Agents held by the whole instance | 200 | `DEMO_MAX_AGENTS` |
| Authorize calls per agent | 40 | `DEMO_MAX_ACTIONS_PER_AGENT` |
| Lifetime of an agent and its audit rows | 60 minutes | `DEMO_TTL_MINUTES` |

- The client is found with the SDK's `trustedProxy` setting and `trustedHeader: "cf-connecting-ip"`. Cloudflare overwrites that header, so it cannot be forged by a visitor. `x-forwarded-for` is ignored.
- The per request limiter is the SDK's in-memory `createRateLimiter`. It is per Worker isolate, so it slows a single client down but is not a global counter. The agent caps live in D1 and are global.
- Expiry has three layers: agent tokens carry an expiry equal to the TTL, a cron trigger runs every 15 minutes and deletes expired agents with their permissions and audit rows, and agent creation also runs the same cleanup at most once a minute.
- The only owner row is `demo-owner@example.invalid`. Agent names are restricted to letters, digits, spaces, dash and underscore, and the page asks visitors not to type personal data.
- The Worker makes no outbound requests, and the page loads no third party scripts, fonts or images (a CSP with a per response nonce enforces this).
- IP addresses are never written to the database. To enforce the per client cap, the agent's metadata holds a 12 byte SHA-256 fingerprint of the IP, keyed with a secret and the UTC date. It is deleted with the agent. Set `DEMO_CLIENT_SALT` so the fingerprint cannot be brute forced from the small IPv4 space. Without it the Worker uses a random per isolate value, which keeps the cap working inside one isolate only.

## Run it locally

Cloudflare tooling is not needed for the Node fallback, which uses the SDK's in-memory SQLite provider.

```bash
pnpm install
pnpm --filter @glinr/theauth build          # the example imports the built core
pnpm --filter @glinr/theauth-example-demo-worker dev:node
# http://localhost:8787
```

The Node entry is `src/node.ts`. It raises the per client caps because a local run has no proxy header, so every request shares one bucket. Set `PORT` and any `DEMO_*` variable to change behaviour.

To run the real Worker with a local D1 database (no Cloudflare account needed):

```bash
cd examples/demo-worker
pnpm wrangler d1 migrations apply theauth-demo --local
pnpm dev                                   # wrangler dev
```

`wrangler dev` serves cron triggers at `/cdn-cgi/handler/scheduled` if you want to test cleanup.

## Tests

```bash
pnpm --filter @glinr/theauth-example-demo-worker test
```

The Vitest suite imports the app and drives the routes against in-memory SQLite: create an agent, allowed, denied, audit rows, revoke then denied, the per client rate limit (including that `x-forwarded-for` cannot dodge it), the agent caps, input validation and cleanup. A separate test fails when `migrations/0001_init.sql` drifts from what the SDK would create.

## Deploy (owner steps)

Run these from `examples/demo-worker` with a Cloudflare account that can create D1 databases and Workers.

```bash
# 1. Create the database and copy the printed database_id into wrangler.toml
pnpm wrangler d1 create theauth-demo

# 2. Create the tables (one migration)
pnpm wrangler d1 migrations apply theauth-demo --remote

# 3. Optional but recommended: key the client fingerprint
pnpm wrangler secret put DEMO_CLIENT_SALT   # paste a long random string

# 4. Deploy
pnpm wrangler deploy
```

Then, in the Cloudflare dashboard:

- Check that the cron trigger (`*/15 * * * *`) is listed under the Worker's Triggers tab.
- If you attach a custom domain, put it behind Cloudflare so `cf-connecting-ip` is always set. Do not point another proxy at the Worker, because the `trustedHeader` setting assumes Cloudflare is the only edge.
- Consider a Cloudflare rate limiting rule on `/api/*` as a global counter in front of the per isolate limiter.

Once a deploy is live and verified, the URL can be added to the project README. This folder intentionally contains none.

## What to configure

| Where | What |
| --- | --- |
| `wrangler.toml` `database_id` | The id from `wrangler d1 create`. Placeholder until then. |
| `wrangler.toml` `[vars]` | Optional limits. |
| Secret `DEMO_CLIENT_SALT` | Optional, keys the client fingerprint. |

## Notes on D1

- `createTheAuth` with `provider: "d1"` does not create tables itself: `createTables` has no D1 executor and throws `unsupported provider "d1"`. The Worker therefore sets `skipMigrations: true` and the schema ships as `migrations/0001_init.sql`.
- The SDK returns a denial for a revoked agent before it reaches the audit writer, so that denial has no audit row. The demo inserts one with `insertAuditRow` so the table shows the retry after revocation.
- Audit timestamps have one second resolution, so rows written in the same second can appear in either order.
- Fonts: the page names Inter and JetBrains Mono and falls back to system fonts. It does not fetch web fonts, to keep the page free of third party requests. Self host the font files if you want them guaranteed.
