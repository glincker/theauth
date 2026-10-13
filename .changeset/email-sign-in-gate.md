---
"@glinr/theauth-email": minor
---

Email and password sign-in now consults the core sign-in gate when the core exposes `ctx.signInGate`: a forced password change answers 403 `PASSWORD_RESET_REQUIRED` with a challenge, and a required second factor answers `{ twoFactorRequired: true, challenge }`. A completed password reset clears the forced change flag, and any password change revokes trusted devices. `auth.session.maxConcurrent` and `onLimit` are honored for sessions this package creates. `createEmailAuth` accepts `signInGate` and `sessionLimit` directly.
