---
"@glinr/theauth": minor
---

Postgres now works across the whole instance. Before this release the core modules sent SQLite-shaped values to Postgres, so the first write (for example `user.create`) and every JSON read failed.

Timestamps on Postgres are now `BIGINT` epoch seconds, the same as SQLite. JSON stays `JSONB` and flags stay `BOOLEAN`. Migration `0003-epoch-timestamps` converts existing `TIMESTAMPTZ` columns in place. Run `theauth db up` (or let the instance migrate on start) after upgrading. If you query the tables yourself, wrap timestamp columns in `to_timestamp(...)`.

MySQL is marked unsupported until it passes the test suite on a real server. `provider: "mysql"` now throws `THEAUTH_MYSQL_UNSUPPORTED` unless you pass `experimental: true`.

Audit hashes are unchanged, so existing chains and the Go verifier keep verifying.
