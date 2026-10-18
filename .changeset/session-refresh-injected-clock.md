---
"@glinr/theauth": patch
---

The cookie session manager now checks the session expiry during refresh against the clock you pass in `now`, not the real clock. Production behavior is unchanged when `now` is not set.
