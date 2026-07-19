---
title: OAuth Providers
description: OAuth and social sign-in providers available in TheAuth. Configure any provider via the oauth() plugin.
---

# OAuth Providers

TheAuth includes built-in OAuth provider configurations. Add one or more via the `oauth()` plugin.

## Setup

```typescript
import { createTheAuth } from '@glinr/theauth';
import { oauth } from '@glinr/theauth/auth';

const kavach = await createTheAuth({
  database: { provider: 'postgres', url: process.env.DATABASE_URL! },
  secret: process.env.KAVACH_SECRET!,
  baseUrl: 'https://auth.example.com',
  plugins: [
    oauth({
      providers: [
        {
          id: 'google',
          clientId: process.env.GOOGLE_CLIENT_ID!,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
        },
        {
          id: 'github',
          clientId: process.env.GITHUB_CLIENT_ID!,
          clientSecret: process.env.GITHUB_CLIENT_SECRET!,
        },
      ],
    }),
  ],
});
```

## Supported providers

The following providers have first-class configurations shipped in the package:

| Provider | ID | Notes |
|---|---|---|
| Apple | `apple` | Requires `.p8` key, team ID, key ID |
| Atlassian | `atlassian` | |
| Auth0 | `auth0` | Requires your Auth0 domain |
| Bitbucket | `bitbucket` | |
| Coinbase | `coinbase` | |
| Discord | `discord` | |
| Dropbox | `dropbox` | |
| Facebook | `facebook` | |
| Figma | `figma` | |
| GitHub | `github` | |
| GitLab | `gitlab` | |
| Google | `google` | |
| HuggingFace | `huggingface` | |
| Kakao | `kakao` | |
| Kick | `kick` | |
| LINE | `line` | |
| Linear | `linear` | |
| LinkedIn | `linkedin` | |
| Microsoft | `microsoft` | |
| Naver | `naver` | |
| Notion | `notion` | |
| Okta | `okta` | Requires your Okta domain |
| PayPal | `paypal` | |
| Railway | `railway` | |
| Reddit | `reddit` | |
| Roblox | `roblox` | |
| Salesforce | `salesforce` | |
| Slack | `slack` | |
| Spotify | `spotify` | |
| TikTok | `tiktok` | |
| Twitch | `twitch` | |
| Twitter / X | `twitter` | OAuth 2.0 with PKCE |
| VK | `vk` | |
| WeChat | `wechat` | |
| Yahoo | `yahoo` | |
| Zoom | `zoom` | |

## Generic OIDC provider

For any OIDC-compliant identity provider not in the list above:

```typescript
oauth({
  providers: [
    {
      id: 'custom-idp',
      name: 'My IdP',
      type: 'oidc',
      issuer: 'https://idp.example.com',
      clientId: process.env.IDP_CLIENT_ID!,
      clientSecret: process.env.IDP_CLIENT_SECRET!,
      scope: 'openid email profile',
    },
  ],
})
```

## Account linking

When a user signs in with a new OAuth provider that uses the same email as an existing account, TheAuth links the provider to the existing user record by default.

!!! warning "Verify"
    Verify the account linking behavior for your app by reading the `oauth()` plugin source or checking the package README before relying on automatic linking in production. Automatic linking can be disabled if your app requires explicit user consent.

## Additional OAuth methods

| Method | Plugin | Description |
|---|---|---|
| Passkeys | `passkey()` | WebAuthn / FIDO2 biometrics |
| Magic link | `magicLink()` | Passwordless single-use email link |
| Email OTP | `emailOtp()` | 6-digit code via email |
| Phone OTP | `phone()` | SMS OTP, any provider |
| SIWE | `siwe()` | Sign-In with Ethereum (EIP-4361) |
| Device code | `device()` | For TVs and CLIs |
| One-tap | `oneTap()` | Google one-tap sign-in |
| Anonymous | `anonymous()` | Temporary anonymous identity |

## Related pages

- [Email and Password](email-password.md)
- [Passkeys (WebAuthn)](passkeys.md)
- [Magic Links](magic-links.md)
- [Multi-Factor Auth](multi-factor-auth.md)
