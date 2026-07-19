# @glinr/theauth-expo

Expo / React Native provider and hooks for TheAuth authentication.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-expo?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-expo)

## Install

```bash
npm install @glinr/@glinr/theauth-expo
```

## Usage

Wrap your Expo app with `TheAuthExpoProvider`. Tokens are persisted using the configured storage (defaults to `expo-secure-store`).

```tsx
import { TheAuthExpoProvider, useSession, useUser, useSignIn } from '@glinr/theauth-expo';

export default function App() {
  return (
    <TheAuthExpoProvider
      apiUrl="https://auth.yourapp.com"
      tenantId="your-tenant-id"
    >
      <RootNavigator />
    </TheAuthExpoProvider>
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

- `TheAuthExpoProvider`: context provider with secure storage support (formerly `KavachExpoProvider`, still exported as a deprecated alias)
- `useSession`: current session and loading state
- `useUser`: authenticated user object
- `useSignIn` / `useSignOut` / `useSignUp`: auth actions
- `useAgents`: manage AI agents for the current user
- `useTheAuthContext`: raw context access (formerly `useKavachContext`, still exported as a deprecated alias)

## Docs

[https://docs.theauth.dev](https://docs.theauth.dev)

## License

MIT
