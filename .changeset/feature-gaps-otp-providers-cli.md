---
"@glinr/theauth": minor
"@glinr/theauth-cli": minor
---

Feature-gap pass, all additive.

- Unified OTP: `createOtpService` for email and SMS with purposes (sign-in, verify-email, reset-password, two-factor), resend cooldown, attempt lockout and constant-time checks. Senders: `emailOtpSender` (wraps any email provider), `twilioOtpSender`, `consoleOtpSender`. The email OTP and phone modules gain `resendCooldownSeconds`, and email OTP now compares hashes in constant time.
- Email adapters: `ses` (SigV4 over fetch) and `postmark`. `resend`, `sendgrid` and `smtp` are now exported from `@glinr/theauth/auth`.
- OAuth presets: Keycloak, Authentik, ZITADEL, OneLogin, Gitea, Patreon, Box, Yandex and WordPress.com. `genericOIDC` gains `mapProfile` and `userinfoAuthScheme`.
- CLI: `theauth doctor` (with `--json`), `theauth secret` and `theauth completions`.
