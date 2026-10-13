---
"@glinr/theauth": minor
---

Adapter rate limit counters use the `rateLimit` secondary storage, so one limit holds across instances when a shared store is configured. `guard.admit` is now async.
