---
"@glinr/theauth": minor
---

`createTheAuth` now creates the tables on Cloudflare D1 instead of throwing `createTables: unsupported provider "d1"`. The tables are created in a single D1 batch of `CREATE TABLE IF NOT EXISTS` statements, and plugin migrations also run on D1. A new `getMigrationStatements(provider, config?)` export returns the same SQL so you can write a migration file for `wrangler d1 migrations apply` and set `skipMigrations: true`.
