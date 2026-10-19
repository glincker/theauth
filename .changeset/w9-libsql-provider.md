---
"@glinr/theauth": minor
---

Add `database: { provider: "libsql", url, authToken? }` for Turso and other libSQL servers (or a `file:` URL), backed by the optional `@libsql/client` peer. It migrates with the SQLite schema. The store contract suite passes on a real libSQL file through the provider and through a bring your own `drizzle-orm/libsql` handle. Docs: a new Turso, Neon and Supabase page with a Neon recipe over the WebSocket `Pool`, Supabase connection modes and SSL spelling with `pg` 8.20, and what was run. Adds an opt in contract test for Postgres behind a transaction mode pooler (`THEAUTH_TEST_PG_POOLER_URL`).
