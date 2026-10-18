---
"@glinr/theauth-cli": minor
"@glinr/create-theauth-app": minor
---

`theauth init` and `theauth doctor` rebuilt, and the project templates moved to real storage.

`theauth init` now detects the framework and package manager from `package.json` and writes a working setup: `src/theauth.ts`, a seed script that creates the owner user with `theauth.user.create` before a demo agent (the old example created an agent for a user that did not exist and failed on the foreign key), the mount file for Hono, Express, Fastify, Next.js, SvelteKit or Nuxt, `.env.example`, and a `.env` with generated secrets (added to `.gitignore`). It stores data in a SQLite file, not `:memory:`, and prints a `curl` against the mounted routes. Re-running it never overwrites a file that exists unless you pass `--force`.

`theauth doctor` adds `core-version` (core against the adapter peer range), `schema` (pending migrations from the ledger), `allow-unauthenticated` and `trusted-proxy`. `theauth doctor --live <url>` calls the running server: routes reachable, MCP metadata only lists mounted endpoints, and a protected route answers 401 without a token. The `--json` shape is unchanged (`{ ok, checks }`); new checks only add entries.

Upgrade notes:

- `theauth init` flags changed: `--framework`, `--db`, `--yes`, `--dir`, `--force`, `--mcp`. It no longer writes `theauth.config.ts` or `theauth.example.ts`. `--mcp` is accepted and skipped with a note until the database backed MCP stores exist.
- `create-theauth-app` templates (`hono-mcp`, `next-saas`, `cloudflare-workers`) write a `.env` (or `.dev.vars`) with generated secrets, drop the hard coded dev secrets, create the owner with `user.create`, and add a `doctor` script. SQLite templates now depend on `better-sqlite3` and `provider: "sqlite-native"`, because the `sql.js` provider does not persist its file. The Cloudflare template requires `ADMIN_API_KEY` instead of `allowUnauthenticated`.
- The `hono-mcp` template still keeps MCP clients, codes and tokens in memory. Database backed MCP stores are not available yet.
