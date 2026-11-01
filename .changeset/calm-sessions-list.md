---
"@glinr/theauth": patch
---

`session.list()` now uses the injected clock, like `validate`, so expiry is consistent when a clock is provided. Adds `tsx` as a dev dependency so the audit chain vector test runs in CI.
