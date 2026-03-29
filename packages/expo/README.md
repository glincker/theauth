# @kavachos/expo

Expo / React Native provider and hooks for KavachOS authentication.

[![npm](https://img.shields.io/npm/v/@kavachos/expo?style=flat-square)](https://www.npmjs.com/package/@kavachos/expo)

## Install

```bash
npm install @kavachos/expo
```

## Usage

Wrap your Expo app with `KavachExpoProvider`. Tokens are persisted using the configured storage (defaults to `expo-secure-store`).

```tsx
import { KavachExpoProvider, useSession, useUser, useSignIn } from '@kavachos/expo';

export default function App() {
  return (
    <KavachExpoProvider
      apiUrl="https://auth.yourapp.com"
      tenantId="your-tenant-id"
    >
      <RootNavigator />
    </KavachExpoProvider>
  );
}

function HomeScreen() {
  const { session } = useSession();
  const { user } = useUser();
  const { signIn } = useSignIn();

  return session
    ? <Text>Hello, {user?.email}</Text>
    : <Button title="Sign in" onPress={() => signIn({ email, password })} />;
}
```

## Exports

- `KavachExpoProvider` — context provider with secure storage support
- `useSession` — current session and loading state
- `useUser` — authenticated user object
- `useSignIn` / `useSignOut` / `useSignUp` — auth actions
- `useAgents` — manage AI agents for the current user
- `useKavachContext` — raw context access

## Docs

[https://docs.kavachos.com](https://docs.kavachos.com)

## License

MIT
