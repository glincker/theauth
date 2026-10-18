---
"@glinr/theauth": minor
---

Add an opt-in session idle timeout and remember me. `idleTimeoutMs` (env `THEAUTH_SESSION_IDLE_TIMEOUT_MS`, off by default) denies a session with no recent activity; `lastActiveAt` is rewritten at most once per `activityGranularityMs`. `session.validateDetailed(token)` and the cookie manager's `validateSession` report a `reason` (`idle_timeout`, `expired`, `not_found`, `invalid_token`). `create(userId, metadata, { rememberMe })` gives a longer capped lifetime (`rememberMeMaxAge`, `rememberMeMaxAgeCap`), and `buildSessionCookie` writes a persistent or browser session cookie to match. No schema change: the stamp lives in session metadata. The signed session cookie cache stays opt-in on `createCookieSessionManager` and is now documented as experimental and not revocation safe.
