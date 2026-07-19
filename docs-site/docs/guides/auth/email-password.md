---
title: Email and Password
description: Register and sign in with email and password. Full guide covering verification, password reset, and configuration.
---

# Email and Password

The `emailPassword` plugin handles user registration, sign-in, email verification, and password management. Passwords are hashed with scrypt (N=16384, r=8, p=1) using Node's built-in `node:crypto` module, no extra dependencies.

!!! warning
    Because scrypt uses `node:crypto`, the `emailPassword` plugin requires a Node.js runtime. It does not run on Cloudflare Workers, Deno Deploy, or Vercel Edge Functions as-is. If you need edge runtime support, replace the hasher with PBKDF2 via the Web Crypto API using the `password.hash` and `password.verify` options shown below.

!!! info
    If you prefer username-based auth instead of email, see the [username plugin](oauth-providers.md).

## Setup

!!! warning
    By default, sign-in requires email verification. In development, set `requireVerification: false` to skip this. Without it, users who sign up cannot sign in until they verify their email.

=== "Development"
    ```typescript
    // Development: skip email verification
    emailPassword({
      requireVerification: false,
      onSendVerification: async (email, token) => {
        console.log(`Verify: http://localhost:3000/verify?token=${token}`);
      },
    })
    ```
=== "Production"
    ```typescript
    // Production: require verification
    emailPassword({
      requireVerification: true, // default
      onSendVerification: async (email, token, url) => {
        await sendEmail(email, 'Verify your email', `Click: ${url}`);
      },
    })
    ```

### Full config example

```typescript
import { createTheAuth } from '@glinr/theauth';
import { emailPassword } from '@glinr/theauth/auth';

const kavach = await createTheAuth({
  database: { provider: 'postgres', url: process.env.DATABASE_URL! },
  secret: process.env.KAVACH_SECRET!,
  baseUrl: 'https://auth.example.com',
  plugins: [
    emailPassword({
      requireVerification: true,
      onSendVerification: async (email, token, url) => {
        await mailer.send({ to: email, subject: 'Verify email', html: `<a href="${url}">Verify</a>` });
      },
    }),
  ],
});
```

## Registration

```typescript
const result = await kavach.auth.signUp({
  email: 'user@example.com',
  password: 'securepassword123',
  name: 'Alice',
});

// result.user, result.session (if requireVerification: false)
// or result.user, result.needsVerification: true
```

## Sign-in

```typescript
const result = await kavach.auth.signIn({
  email: 'user@example.com',
  password: 'securepassword123',
});

if (!result.session) {
  throw new Error('Sign-in failed');
}
```

## Password reset

Password reset requires `auth.session` to be configured and a callback to send the reset email.

```typescript
auth: {
  session: {
    secret: process.env.SESSION_SECRET!,
    maxAge: 60 * 60 * 24 * 7,
  },
  passwordReset: {
    resetUrl: 'https://example.com/reset-password',
    tokenTtlSeconds: 3600,
    revokeSessionsOnReset: true,
    minPasswordLength: 10,
    sendResetEmail: async (email, token, url) => {
      await mailer.send({
        to: email,
        subject: 'Reset your password',
        html: `<a href="${url}">Reset password</a>`,
      });
    },
  },
},
```

!!! warning
    Always use an HTTPS URL for `resetUrl` in production. Reset tokens in plain HTTP links can be intercepted in transit or leaked via `Referer` headers.

### Password reset config reference

| Option | Type | Default | Description |
|---|---|---|---|
| `sendResetEmail` | `function` | required | Callback to deliver the reset email. Receives email, raw token, and constructed URL. |
| `resetUrl` | `string` | required | Base URL for the reset page. Token is appended as `?token=...` |
| `tokenTtlSeconds` | `number` | `3600` (1h) | Reset token lifetime in seconds. |
| `revokeSessionsOnReset` | `boolean` | `true` | Revoke all sessions when the password is successfully reset. |
| `minPasswordLength` | `number` | `8` | Minimum new password length. |
| `maxPasswordLength` | `number` | `128` | Maximum new password length. |

## Edge runtime: swap the hasher

To run `emailPassword` on Workers or Deno, replace the scrypt hasher with PBKDF2:

```typescript
emailPassword({
  requireVerification: false,
  password: {
    hash: async (password) => {
      const enc = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
      );
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' },
        keyMaterial, 256
      );
      return `${Buffer.from(salt).toString('hex')}:${Buffer.from(bits).toString('hex')}`;
    },
    verify: async (password, hash) => {
      const [saltHex, hashHex] = hash.split(':');
      const salt = Buffer.from(saltHex, 'hex');
      const enc = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
      );
      const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' },
        keyMaterial, 256
      );
      return Buffer.from(bits).toString('hex') === hashHex;
    },
  },
})
```

## Related pages

- [Passkeys (WebAuthn)](passkeys.md)
- [Magic Links](magic-links.md)
- [Multi-Factor Auth](multi-factor-auth.md)
- [Configuration](../../reference/configuration.md)
