---
"@glinr/theauth": patch
---

Fix the permission simulator dropping `constraints` on delegated permissions. A delegated rate limit, IP allowlist, time window or approval rule could show `allow` in `simulate()`, `simulateMany()` and `effectivePermissions()` while `authorize()` denied. The simulator now keeps delegated constraints and agrees with `authorize()`.
