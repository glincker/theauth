---
"@glinr/theauth": minor
---

Add `databaseHooks`: per-model `before` and `after` hooks for create and update on `user`, `session` and `account`. A `before` hook can return `false` to abort or `{ data }` to replace allowed fields, and it fails closed on a throw, a timeout or a malformed result (`DatabaseHookError`). `after` hooks run once the row is committed and never break the write. Hooks stay outside every single-use claim statement, so magic links, OTP codes, OAuth state and refresh rotation remain atomic. Exports `DatabaseHooks`, `DatabaseHookError` and `createDatabaseHookRunner`. See `docs/database-hooks.mdx`.
