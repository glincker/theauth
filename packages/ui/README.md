# @glinr/theauth-ui

[npm](https://www.npmjs.com/package/@glinr/theauth-ui) · [Source](https://github.com/glincker/theauth/tree/main/packages/ui) · [Docs](https://docs.theauth.dev/ui-components) · [All packages](https://github.com/glincker/theauth#packages)

Headless, slot-based auth UI components for theAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-ui?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-ui)

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Install

```bash
npm install @glinr/theauth-ui
```

## Usage

Drop pre-built components into any React app. All components accept `classNames` for slot-level style overrides.

```tsx
import { AuthCard, SignIn, OAuthButtons } from '@glinr/theauth-ui';

function LoginPage() {
  return (
    <AuthCard>
      <OAuthButtons providers={['google', 'github']} />
      <SignIn
        onSuccess={(session) => router.push('/dashboard')}
        classNames={{ input: 'border-gray-300 rounded-md' }}
      />
    </AuthCard>
  );
}
```

## Components

| Component | Description |
|-----------|-------------|
| `AuthCard` | Wrapper card with consistent layout |
| `SignIn` | Email/password sign-in form |
| `SignUp` | Registration form |
| `ForgotPassword` | Password reset request form |
| `TwoFactorVerify` | TOTP/SMS verification form |
| `OAuthButtons` | OAuth provider button row |
| `UserButton` | Avatar dropdown for signed-in users |

## OAuth icons

All provider icons are exported individually (`GoogleIcon`, `GitHubIcon`, `MicrosoftIcon`, etc.) and as `OAUTH_PROVIDERS` metadata array.

## Docs

[https://docs.theauth.dev/ui-components](https://docs.theauth.dev/ui-components)

## Community

[![Discord](https://img.shields.io/discord/829168897080557579?style=flat-square&logo=discord&logoColor=white&label=discord&color=5865F2)](https://discord.gg/Ar5pcaZB99)

Questions and help in the `#theauth` forum on the [GLINR Discord](https://discord.gg/Ar5pcaZB99).

## License

MIT
