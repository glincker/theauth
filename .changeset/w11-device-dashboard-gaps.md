---
"@glinr/theauth": minor
"@glinr/theauth-dashboard": minor
---

Added `GET /devices/enrollment-tokens` and `devices.listEnrollmentTokens()`, which list tokens with usage and state and never the plaintext. The dashboard Devices page now lists enrollment tokens with a revoke button, and a device can have its groups edited, a credential added or revoked, and a policy bundle issued. The dashboard client no longer reports a network error for a 204 response.

`DELETE /delegations/:id` now answers 204 on the admin API plugin too (it used to answer 200 with `{ revoked }`), sharing one handler with the core route. See the upgrade guide.
