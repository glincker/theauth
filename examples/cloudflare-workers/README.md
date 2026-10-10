# Cloudflare Workers example

TheAuth on Cloudflare Workers with D1 as the database, behind the Hono adapter.

## Set up

```bash
pnpm install
wrangler d1 create theauth-db
```

Paste the `database_id` that command prints into `wrangler.toml`, then create the tables and set the session secret:

```bash
pnpm migrations:apply:local   # local D1 used by `wrangler dev`
pnpm migrations:apply         # the remote database
wrangler secret put SESSION_SECRET
```

## Run and deploy

```bash
pnpm dev
pnpm deploy
```

## How the tables get created

`migrations/0001_initial.sql` holds the `CREATE TABLE IF NOT EXISTS` statements for the features this worker turns on (sessions and agents). `wrangler d1 migrations apply` runs it, and the worker passes `skipMigrations: true`, so requests never spend time checking the schema.

The file is generated from the same function the SDK uses at startup, `getMigrationStatements`:

```bash
pnpm migrations:generate
```

If you enable more features (OAuth, passkeys, an organization plugin, and so on), keep the options in `scripts/generate-migration.mjs` in step with `src/worker.ts`, write the output to a new numbered file such as `0002_more_features.sql` containing only the new tables, and apply it. The statements are idempotent, so a full regenerated file is also safe to apply by hand.

Plugin tables that a plugin registers through `addMigration` are created by the plugin at startup and are not part of this file.

## Skipping the migration file

Remove `skipMigrations: true` from `src/worker.ts` and theAuth creates the missing tables itself, in one D1 batch, the first time an isolate handles a request. That is convenient for a first try. For production, the migration file keeps schema changes in your deploy step instead of in request handling.

## Notes

- The D1 binding replaces the connection URL.
- `wrangler.toml` holds the binding and database name.
- One TheAuth instance is built per isolate and reused across requests.
