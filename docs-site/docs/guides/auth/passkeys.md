---
title: Passkeys (WebAuthn)
description: Authenticate users with WebAuthn passkeys via the passkey() plugin. Covers rpId setup, registration and authentication ceremonies, and credential storage.
---

# Passkeys (WebAuthn)

Passkeys use the WebAuthn standard (FIDO2) to authenticate users with device biometrics (Touch ID, Face ID, Windows Hello) or hardware security keys. No password is ever created or stored.

## Setup

### 1. Install

```bash
pnpm add @glinr/theauth
```

### 2. Add the plugin

```typescript
import { createAuth } from '@glinr/theauth';
import { passkey } from '@glinr/theauth/auth';

const kavach = await createAuth({
  database: { provider: 'postgres', url: process.env.DATABASE_URL! },
  secret: process.env.KAVACH_SECRET!,
  baseUrl: 'https://auth.example.com',
  plugins: [
    passkey({
      rpName: 'My App',           // Shown in the browser prompt
      rpId: 'example.com',        // Must match your domain, no protocol
    }),
  ],
});
```

!!! warning
    `rpId` must be a registrable domain suffix of the origin. For `https://app.example.com`, valid values are `app.example.com` or `example.com`. Localhost works during development.

## Registration ceremony

Passkey registration is a two-step ceremony:

**Step 1.** Request registration options from the server.

```typescript
// Server: generate registration options
const options = await kavach.auth.passkey.generateRegistrationOptions({
  userId: user.id,
  userName: user.email,
});
```

**Step 2.** Complete registration with the credential from the browser.

```typescript
// Server: verify registration response
const credential = await kavach.auth.passkey.verifyRegistrationResponse({
  userId: user.id,
  response: credentialFromBrowser,
  expectedChallenge: storedChallenge,
});
```

## Authentication ceremony

**Step 1.** Request authentication options.

```typescript
const options = await kavach.auth.passkey.generateAuthenticationOptions();
```

**Step 2.** Verify the response.

```typescript
const result = await kavach.auth.passkey.verifyAuthenticationResponse({
  response: credentialFromBrowser,
  expectedChallenge: storedChallenge,
});

if (result.verified) {
  // create session for result.userId
}
```

## Session freshness

Passkey registration requires a fresh session (authenticated recently). If the user's session is older than `freshAge` (default 5 minutes), redirect them to re-authenticate before allowing passkey registration.

## Related pages

- [Email and Password](email-password.md)
- [Magic Links](magic-links.md)
- [Multi-Factor Auth](multi-factor-auth.md)
- [Sessions](../../concepts/sessions.md)
