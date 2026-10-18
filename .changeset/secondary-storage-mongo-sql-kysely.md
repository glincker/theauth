---
"@glinr/theauth": minor
---

Add three secondary storage backends: `mongoStorage(collection)` for MongoDB 4.4+, `sqlStorage({ dialect, run })` for any SQL database including Microsoft SQL Server, and `kyselyStorage(db, { dialect, CompiledQuery })` for any Kysely dialect. None adds a dependency; you pass your own client. All keep exact per key counters and follow the same `SecondaryStorage` contract as the memory, database and Redis backends.

Fix: `redisStorage().incr()` threw `value is not an integer` when the key held plain text written by `set()`. It now restarts the window like the other backends.
