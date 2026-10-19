# @glinr/theauth-test-utils

## 0.3.0

### Minor Changes

- 3e3855c: Add `database: { drizzle, dialect }` to pass an existing Drizzle instance (`"sqlite"`, `"postgres"` or `"mysql"`) instead of a URL. It goes through the same `DatabaseOpener` seam, migrations use the dialect, and `skipMigrations` works as before. See `docs/bring-your-own-drizzle.mdx`.

  Add `StoreConflictError`, exported from `@glinr/theauth`. The nine places that rely on a unique index (user create, audit chain append, quorum vote, ban insert, erasure tombstones, MCP client, revocation and block inserts) now read structured driver codes first and keep the text match as a fallback, so behavior on the current providers is unchanged.

  Fix SCIM group `PUT`: it deleted every member and re-inserted the list, so a member who stayed left the group for a moment, got a new row id, and lost any role other than `member`. It now removes only members missing from the list and adds only the new ones.

  `@glinr/theauth-test-utils` gains a `./store-contract` subpath with `runStoreContract`: claim races with 24 parallel callers, unique conflicts and audit chain order, for any backend. `vitest` is an optional peer dependency.

## 0.2.0

### Minor Changes

- 0fa5b1e: Remove the legacy KavachOS naming. The deprecated `Kavach*` and `createKavach` exports are gone: use `TheAuth*` and `createTheAuth`. Environment variables are now `THEAUTH_*`, webhook headers `X-TheAuth-*`, cookies and the default API route use `theauth`, and database tables are `theauth_*` (existing `kavach_*` tables are renamed in place by `createTables`, no data is lost). `Auth*` aliases remain deprecated.

## 0.1.0

### Minor Changes

- 94804ec: Launch release: promote core and primary client-facing packages to the 0.1 line.

  Highlights:

  - Stabilize package exports and build artifacts for launch.
  - Ship improved CLI version handling and launch docs.
  - Keep adapters/plugins/dashboard on existing release tracks for a separate coordinated versioning pass.
