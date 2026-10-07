# @glinr/theauth-expo

Expo / React Native provider and hooks for theAuth authentication.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-expo?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-expo)

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Install

```bash
npm install @glinr/theauth-expo
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

- `TheAuthExpoProvider`: context provider with secure storage support (formerly `TheAuthExpoProvider`, still exported as a deprecated alias)
- `useSession`: current session and loading state
- `useUser`: authenticated user object
- `useSignIn` / `useSignOut` / `useSignUp`: auth actions
- `useAgents`: manage AI agents for the current user
- `useTheAuthContext`: raw context access (formerly `useTheAuthContext`, still exported as a deprecated alias)

## Docs

[https://docs.theauth.dev](https://docs.theauth.dev)

## Community

[![Discord](https://img.shields.io/discord/829168897080557579?style=flat-square&logo=discord&logoColor=white&label=discord&color=5865F2)](https://discord.gg/Ar5pcaZB99)

Questions and help in the `#theauth` forum on the [GLINR Discord](https://discord.gg/Ar5pcaZB99).

## License

MIT
