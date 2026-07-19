---
title: Magic Links
description: Issue signed, single-use email links for passwordless sign-in with magicLink(). Configure token expiry, a send function, and the post-verification redirect.
---

# Magic Links

Magic links let users sign in by clicking a link sent to their email. No password needed. The link is a signed, single-use token that expires after a configurable window.

## Setup

```typescript
import { createTheAuth } from '@glinr/theauth';
import { magicLink } from '@glinr/theauth/auth';

const kavach = await createTheAuth({
  database: { provider: 'postgres', url: process.env.DATABASE_URL! },
  secret: process.env.KAVACH_SECRET!,
  baseUrl: 'https://auth.example.com',
  plugins: [
    magicLink({
      onSendLink: async (email, url) => {
        await resend.emails.send({
          from: 'auth@example.com',
          to: email,
          subject: 'Your sign-in link',
          html: `<a href="${url}">Sign in</a>`,
        });
      },
      expiresIn: 600, // seconds, default 600 (10 minutes)
      redirectTo: '/dashboard',
    }),
  ],
});
```

## Sending a magic link

```typescript
await kavach.auth.magicLink.sendLink({
  email: 'user@example.com',
});
// Calls your onSendLink callback with the signed URL
```

## Verifying the token

When the user clicks the link, verify the token from the URL query string:

```typescript
const result = await kavach.auth.magicLink.verify({
  token: searchParams.get('token')!,
});

if (result.session) {
  // User is authenticated, redirect to dashboard
}
```

## Config reference

| Option | Type | Default | Description |
|---|---|---|---|
| `onSendLink` | `function` | required | Callback that delivers the magic link email. Receives the email address and the signed URL. |
| `expiresIn` | `number` | `600` | Token lifetime in seconds. |
| `redirectTo` | `string` | `'/'` | Path to redirect the user after successful verification. |

!!! info
    Magic link tokens are single-use and invalidated immediately after verification. Clicking the link twice results in an error on the second click.

## Related pages

- [Email and Password](email-password.md)
- [Passkeys (WebAuthn)](passkeys.md)
- [Multi-Factor Auth](multi-factor-auth.md)
