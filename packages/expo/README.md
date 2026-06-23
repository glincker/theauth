# @glinr/theauth-expo

Expo / React Native provider and hooks for TheAuth authentication.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-expo?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-expo)

## Install

```bash
npm install @glinr/@glinr/theauth-expo
```

## Usage

Wrap your Expo app with `KavachExpoProvider`. Tokens are persisted using the configured storage (defaults to `expo-secure-store`).

```tsx
import { KavachExpoProvider, useSession, useUser, useSignIn } from '@glinr/theauth-expo';

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

- `KavachExpoProvider`: context provider with secure storage support
- `useSession`: current session and loading state
- `useUser`: authenticated user object
- `useSignIn` / `useSignOut` / `useSignUp`: auth actions
- `useAgents`: manage AI agents for the current user
- `useKavachContext`: raw context access

## Docs

[https://docs.theauth.dev](https://docs.theauth.dev)

## License

MIT
