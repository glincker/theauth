---
title: React
description: Wire TheAuth into React 18 apps via AuthProvider and hooks from @glinr/theauth-react. Supports Next.js App Router, Pages Router, Vite, and edge runtime backends.
---

# React

`@glinr/theauth-react` provides React hooks and a context provider for building auth UIs on top of TheAuth. It works with Next.js App Router, Next.js Pages Router, Vite, and any React 18+ setup.

The package has no Node.js dependencies. It runs entirely in the browser and talks to your TheAuth API handler over standard `fetch`.

!!! info
    All hooks must be rendered inside `AuthProvider`. The provider talks to your TheAuth API route; no direct database access from the browser.

## Installation

```bash
pnpm add @glinr/theauth-react
```

## Provider setup

Wrap your app with `AuthProvider`. In Next.js App Router, create a client component and import it from your root layout.

```tsx
// app/providers.tsx
'use client';
import { AuthProvider } from '@glinr/theauth-react';

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider basePath="/api/kavach">
      {children}
    </AuthProvider>
  );
}
```

```tsx
// app/layout.tsx
import { Providers } from './providers';

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
```

| Prop | Type | Default | Description |
|---|---|---|---|
| `basePath` | `string` | `"/api/kavach"` | Path to your TheAuth API handler. Must match the route you mounted in the adapter. |
| `fetchOptions` | `RequestInit` | undefined | Merged into every fetch call. Use this to add custom headers or credentials mode. |

## useUser

Returns the current user and loading state.

```tsx
import { useUser } from '@glinr/theauth-react';

function Header() {
  const { user, isAuthenticated, isLoading } = useUser();

  if (isLoading) return <span>Loading...</span>;
  if (!isAuthenticated) return <a href="/login">Sign in</a>;
  return <span>Hello, {user.name}</span>;
}
```

## useSignIn

```tsx
import { useSignIn } from '@glinr/theauth-react';

function LoginForm() {
  const { signIn, isLoading, error } = useSignIn();

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    await signIn({
      email: form.get('email') as string,
      password: form.get('password') as string,
    });
  }

  return (
    <form onSubmit={handleSubmit}>
      <input name="email" type="email" />
      <input name="password" type="password" />
      {error && <p>{error.message}</p>}
      <button type="submit" disabled={isLoading}>Sign in</button>
    </form>
  );
}
```

## useSignOut

Signs the user out and clears the local session.

```tsx
import { useSignOut } from '@glinr/theauth-react';

function NavBar() {
  const { signOut } = useSignOut();

  return (
    <nav>
      <button onClick={() => signOut({ redirectTo: '/login' })}>
        Sign out
      </button>
    </nav>
  );
}
```

## useAgents

Lets your UI create, list, and revoke agents without a custom API route.

```tsx
import { useAgents } from '@glinr/theauth-react';

function Dashboard() {
  const { agents, create, revoke, isLoading } = useAgents();

  async function handleCreate() {
    await create({
      name: 'my-bot',
      type: 'autonomous',
      permissions: [
        { resource: 'reports:*', actions: ['read'] },
      ],
    });
  }

  return (
    <div>
      <button onClick={handleCreate}>New agent</button>
      {isLoading && <p>Loading agents...</p>}
      {agents.map((agent) => (
        <div key={agent.id}>
          <span>{agent.name}</span>
          <button onClick={() => revoke(agent.id)}>Revoke</button>
        </div>
      ))}
    </div>
  );
}
```

| Field | Type | Description |
|---|---|---|
| `agents` | `Agent[]` | Current list of agents for the authenticated user. |
| `create` | `function` | Create a new agent. The list refreshes automatically on success. |
| `revoke` | `function` | Revoke an agent by ID. Removes it from the local list on success. |
| `refetch` | `function` | Re-fetch the agent list manually. |
| `isLoading` | `boolean` | True during the initial agents fetch. |

## Related pages

- [Expo / React Native](expo.md)
- [Agent Identity](../../concepts/agents.md)
- [Next.js App Router](../frameworks/nextjs.md)
