---
"@glinr/theauth": patch
---

Fix the hourly call budget (`maxCallsPerHour`, table `theauth_rate_limits`). It read the counters and then wrote one back, so parallel calls could all see room and pass the limit (24 parallel calls against a limit of 10 all got through). The count is now reserved first with one guarded increment (or an insert on a deterministic bucket id), then summed, and a call over the limit hands its slot back. It uses the store kernel on SQLite, Postgres and MySQL. A call may be refused when it would have just fit, but the budget is never exceeded. The store contract suite gains a 24 way race for it.

Also declares the migration 0014 hot path indexes in the Drizzle schema objects.
