---
"@glinr/theauth": minor
---

`createStatelessSessions` now refuses token cookies written before the identity binding by default (`acceptLegacyTokenCookies` was `true`). Set it to `true` for one cookie lifetime when upgrading with live sessions; otherwise affected users sign in again once.
