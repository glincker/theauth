---
"@glinr/theauth": minor
---

`databaseHooks.user.update` now fires for admin ban, unban and forced password reset, additional fields, email verification, anonymous upgrade, SCIM replace, patch and deactivate, and Stripe and Polar billing writes. `databaseHooks.user.create` now fires for anonymous, username, Google One Tap and SCIM sign-ups. Semantics are the same as before: `before` fails closed, only `email`, `name` and `metadata` can be replaced, `after` errors are swallowed, and no hook runs inside a single-use claim statement. A SCIM write stopped by a hook answers 403, a billing webhook stopped by a hook answers 500 so the provider retries. Also fixes magic link and email OTP sign-ups ignoring a `name` or `metadata` replacement from a `before` hook. GDPR erasure, `deleteUser` and the importers deliberately bypass hooks.
