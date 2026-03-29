# @kavachos/react

React provider and hooks for KavachOS authentication.

[![npm](https://img.shields.io/npm/v/@kavachos/react?style=flat-square)](https://www.npmjs.com/package/@kavachos/react)

## Install

```bash
npm install @kavachos/react
```

## Usage

Wrap your app with `KavachProvider`, then use hooks anywhere in the tree.

```tsx
import { KavachProvider, useSession, useUser, useSignIn, useSignOut } from '@kavachos/react';

function App() {
  return (
    <KavachProvider apiUrl="https://auth.yourapp.com" tenantId="your-tenant-id">
      <Dashboard />
    </KavachProvider>
  );
}

function Dashboard() {
  const { session, isLoading } = useSession();
  const { user } = useUser();
  const { signIn } = useSignIn();
  const { signOut } = useSignOut();

  if (isLoading) return <p>Loading...</p>;
  if (!session) return <button onClick={() => signIn({ email, password })}>Sign in</button>;

  return (
    <div>
      <p>Welcome, {user?.email}</p>
      <button onClick={signOut}>Sign out</button>
    </div>
  );
}
```

## Exports

- `KavachProvider` — context provider, wrap your app root
- `useSession` — current session and loading state
- `useUser` — authenticated user object
- `useSignIn` — sign-in action
- `useSignOut` — sign-out action
- `useSignUp` — sign-up action
- `useAgents` — manage AI agents for the current user
- `useKavachContext` — raw context access

## Docs

[https://docs.kavachos.com](https://docs.kavachos.com)

## License

MIT
