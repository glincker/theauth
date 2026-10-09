---
"@glinr/theauth": minor
---

OTP over HTTP, all opt-in. `otpRoutes` plugin adds `POST /auth/code/send` and `/auth/code/verify` (rate limited, enumeration safe). `twoFactor({ otp })` adds email or SMS codes as a second method, and `passwordReset.otp` adds `requestResetOtp` and `resetPasswordWithOtp` plus matching routes. Fix: the Facebook preset now maps the Graph API `id` to the profile id, so sign-in no longer fails with a missing `sub` error.
