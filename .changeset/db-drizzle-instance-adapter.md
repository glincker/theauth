---
"@glinr/theauth": minor
"@glinr/theauth-test-utils": minor
---

Add `database: { drizzle, dialect }` to pass an existing Drizzle instance (`"sqlite"`, `"postgres"` or `"mysql"`) instead of a URL. It goes through the same `DatabaseOpener` seam, migrations use the dialect, and `skipMigrations` works as before. See `docs/bring-your-own-drizzle.mdx`.

Add `StoreConflictError`, exported from `@glinr/theauth`. The nine places that rely on a unique index (user create, audit chain append, quorum vote, ban insert, erasure tombstones, MCP client, revocation and block inserts) now read structured driver codes first and keep the text match as a fallback, so behavior on the current providers is unchanged.

Fix SCIM group `PUT`: it deleted every member and re-inserted the list, so a member who stayed left the group for a moment, got a new row id, and lost any role other than `member`. It now removes only members missing from the list and adds only the new ones.

`@glinr/theauth-test-utils` gains a `./store-contract` subpath with `runStoreContract`: claim races with 24 parallel callers, unique conflicts and audit chain order, for any backend. `vitest` is an optional peer dependency.
