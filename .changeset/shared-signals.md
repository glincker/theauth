---
"@glinr/theauth": minor
---

OpenID Shared Signals Framework 1.0 with CAEP and RISC. New `sharedSignals()` plugin (also at `@glinr/theauth/signals`) mounts an SSF transmitter (stream management, status, subjects, verification, push per RFC 8935 with retry and SSRF-safe URLs, poll per RFC 8936) and a receiver that verifies Security Event Tokens (RFC 8417) and revokes local sessions on session-revoked, sessions-revoked and account-disabled. Emission is opt in through new `onPasswordChanged` (password reset), `onChange` (TOTP) and `onCredentialChange` (passkey) callbacks plus the existing session `onRevoke` and admin `onAdminAction`. Adds the `theauth_ssf_*` tables when the plugin is present.
