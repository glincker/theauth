---
title: Multi-Factor Auth
description: Add TOTP second-factor authentication via the twoFactor plugin. QR code enrollment, 6-digit verification, and backup codes for any RFC 6238 authenticator.
---

# Multi-Factor Auth

The `twoFactor()` plugin adds TOTP (time-based one-time password) support compatible with Google Authenticator, Authy, 1Password, and any RFC 6238 app. Users enroll once by scanning a QR code, then provide a 6-digit code on every sign-in.

## Setup

```typescript
import { createTheAuth } from '@glinr/theauth';
import { emailPassword } from '@glinr/theauth/auth';
import { twoFactor } from '@glinr/theauth/auth';

const kavach = await createTheAuth({
  database: { provider: 'postgres', url: process.env.DATABASE_URL! },
  secret: process.env.KAVACH_SECRET!,
  baseUrl: 'https://auth.example.com',
  plugins: [
    emailPassword(),
    twoFactor({
      issuer: 'My App',  // Shown in the authenticator app
    }),
  ],
});
```

## Enrollment

**Step 1.** Generate a TOTP secret and QR code for the user.

```typescript
const { secret, qrCodeUrl, backupCodes } = await kavach.auth.twoFactor.setup({
  userId: user.id,
});

// Display qrCodeUrl as a QR code for the user to scan
// Store backupCodes for the user to save securely
```

**Step 2.** Confirm enrollment by verifying a code from the authenticator app.

```typescript
await kavach.auth.twoFactor.enable({
  userId: user.id,
  code: codeFromApp,
});
```

## Verification during sign-in

After the primary credential (email/password) is verified, prompt for the TOTP code:

```typescript
const result = await kavach.auth.twoFactor.verify({
  userId: user.id,
  code: totpCode,
});

if (result.verified) {
  // Issue the session
}
```

## Backup codes

Backup codes are one-time use and generated during enrollment. Each code is hashed at rest.

```typescript
// Regenerate backup codes (invalidates previous ones)
const { backupCodes } = await kavach.auth.twoFactor.regenerateBackupCodes({
  userId: user.id,
  code: totpCode, // require current TOTP to regenerate
});
```

## Disabling 2FA

```typescript
await kavach.auth.twoFactor.disable({
  userId: user.id,
  code: totpCode, // require current TOTP to disable
});
```

## Related pages

- [Email and Password](email-password.md)
- [Passkeys (WebAuthn)](passkeys.md)
- [Sessions](../../concepts/sessions.md)
