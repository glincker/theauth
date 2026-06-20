# @theauth/ui

Headless, slot-based auth UI components for TheAuth.

[![npm](https://img.shields.io/npm/v/@theauth/ui?style=flat-square)](https://www.npmjs.com/package/@theauth/ui)

## Install

```bash
npm install @theauth/ui
```

## Usage

Drop pre-built components into any React app. All components accept `classNames` for slot-level style overrides.

```tsx
import { AuthCard, SignIn, OAuthButtons } from '@theauth/ui';

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

[https://docs.theauth.com/ui](https://docs.theauth.com/ui)

## License

MIT
