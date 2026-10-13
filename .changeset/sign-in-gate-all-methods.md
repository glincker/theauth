---
"@glinr/theauth": minor
---

Sign-in gate covers every session-issuing path. `SignInMethod` gains `phone`, `email_otp`, `one_tap`, `siwe` and `device` (exported as `SIGN_IN_METHODS`). Phone verify, email OTP verify, Google One Tap and the device-auth plugin now call the gate before issuing a session and answer with `SignInGateError` or the standard challenge response. The `require2faFor` default is unchanged (password, social, magic_link), so the new methods only ask for a second factor when you list them; a forced password change applies to them as it does to the other methods. `createPhoneAuthModule`, `createEmailOtpModule` and `createOneTapModule` take an optional trailing `signInGate`, and `verifyCode` accepts `{ request }` for trusted-device cookies. `createDeviceAuthModule`'s `issueToken` may throw `SignInGateError` to answer the token poll with a challenge. SIWE only verifies a signature and issues no session, so it has no call site yet; the `siwe` method name is reserved for apps that mint a session from it.

New `createPasskeyTwoFactorFactor(passkey)` makes a registered passkey usable as a second factor (`signInGate.factors`). The code sent to `/auth/sign-in/two-factor` is the WebAuthn assertion as JSON or base64url JSON, verified by the passkey module and required to belong to the challenged user.

Stateless sessions accept `signInGate`, `gateMethod` and a per call `{ request, method }` context. `createSession` then fails with `TWO_FACTOR_REQUIRED` or `PASSWORD_RESET_REQUIRED` and the challenge in `error.details`, issuing no cookies.
