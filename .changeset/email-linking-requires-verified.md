---
"@glinr/theauth": patch
---

Close account pre-hijacking through email matching (GHSA draft pending).

- Google One Tap linked a sign-in to any existing account with the same email, ignoring `email_verified` and the local verification state. It now needs both sides verified, matches the address case-insensitively and stores new users as verified only when Google says so. Otherwise it answers 409 `ACCOUNT_EXISTS`.
- Magic link and email OTP now mark the address verified on redemption. On an account that was still unverified they delete the password, linked providers, passkeys and sessions created before the mailbox was proven, so an earlier sign-up with the victim's address no longer survives the victim's first sign-in.
- New options: `unsafeAllowUnverifiedEmailLinking` on `oneTap()` and `oauth()`, `keepUnverifiedCredentials` on `magicLink` and `emailOtp`. All default to the safe behavior.
- Fixed the OAuth docs, which still said new users are always stored as verified.
