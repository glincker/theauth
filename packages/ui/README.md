# @kavachos/ui

Headless, slot-based auth UI components for KavachOS.

[![npm](https://img.shields.io/npm/v/@kavachos/ui?style=flat-square)](https://www.npmjs.com/package/@kavachos/ui)

## Install

```bash
npm install @kavachos/ui
```

## Usage

Drop pre-built components into any React app. All components accept `classNames` for slot-level style overrides.

```tsx
import { AuthCard, SignIn, OAuthButtons } from '@kavachos/ui';

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

[https://docs.kavachos.com/ui](https://docs.kavachos.com/ui)

## License

MIT
