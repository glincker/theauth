---
"@glinr/theauth": major
---

`provider: "sqlite"` now throws `THEAUTH_SQLITE_NOT_PERSISTENT` at startup when `url` is anything other than `:memory:` (or empty). That provider runs on sql.js, an in-memory engine that does not reliably write the database file, so a file URL looked like it worked and then lost the data on restart. The error tells you what to do: use `provider: "sqlite-native"` (better-sqlite3, `npm install better-sqlite3`) or Postgres for a database file, or pass `url: ":memory:"` for an ephemeral database. The old behavior of loading an existing file into sql.js is removed. Docs, READMEs and examples that passed a file URL now use `sqlite-native`.
