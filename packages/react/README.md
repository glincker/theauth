# @theauth/react

React provider and hooks for TheAuth authentication.

[![npm](https://img.shields.io/npm/v/@theauth/react?style=flat-square)](https://www.npmjs.com/package/@theauth/react)

## Install

```bash
npm install @theauth/react
```

## Usage

Wrap your app with `KavachProvider`, then use hooks anywhere in the tree.

```tsx
import { KavachProvider, useSession, useUser, useSignIn, useSignOut } from '@theauth/react';

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

- `KavachProvider`: context provider, wrap your app root
- `useSession`: current session and loading state
- `useUser`: authenticated user object
- `useSignIn`: sign-in action
- `useSignOut`: sign-out action
- `useSignUp`: sign-up action
- `useAgents`: manage AI agents for the current user
- `useRotateSession`: trigger / observe access-token rotation (v0.5+)
- `useKavachContext`: raw context access

## External mode with rotation (v0.5+)

When TheAuth sits behind another auth API (Java/Go/Python), you can run the
provider in **external mode**. Pass an `external` config object instead of
relying on the local managed flow. Set `refreshPath` to opt into the rotation
loop — proactive refresh, exponential-backoff retries, online/offline
recovery, and reuse-detection callbacks all come along for the ride.

```tsx
import { KavachProvider, useRotateSession } from "@theauth/react";

function App() {
  return (
    <KavachProvider
      external={{
        apiUrl: "https://api.example.com",
        mePath: "/api/auth/me",
        loginPath: "/auth/github",
        logoutPath: "/auth/logout",

        // ── v0.5 rotation ──────────────────────────────────────
        refreshPath: "/auth/refresh",
        proactiveRefreshLeadMs: 120_000, // rotate 2 min before expiry
        retry: {
          maxRetries: 3,
          initialDelayMs: 1_000,
          backoffMultiplier: 2,
          maxDelayMs: 10_000,
          requestTimeoutMs: 15_000,
        },

        onAuthError: (code) => {
          // Auth-class failures: send the user back to login.
          if (code === "token_reuse" || code === "family_revoked") {
            window.location.href = "/login?reason=security";
            return;
          }
          window.location.href = "/login";
        },

        onSessionRotated: () => {
          // Refetch authenticated queries with whatever client you use.
          // Apollo example (framework-agnostic — adapt for TanStack Query, urql, etc.):
          //   apolloClient.refetchQueries({ include: "active" });
        },
      }}
    >
      <Dashboard />
    </KavachProvider>
  );
}

function RotateButton() {
  const { rotate, status, isOnline } = useRotateSession();
  return (
    <button onClick={() => rotate()} disabled={!isOnline || status === "rotating"}>
      {status === "rotating" ? "Refreshing…" : "Refresh session"}
    </button>
  );
}
```

### How rotation behaves

- **Single-flight.** Concurrent `rotate()` calls join one in-flight request.
- **Proactive.** When the access token's expiry is known, a timer fires
  `proactiveRefreshLeadMs` before it lapses. On mount, if the cached expiry
  is already inside the lead window, rotation runs immediately. Set
  `proactiveRefreshLeadMs: 0` to disable proactive rotation entirely (manual
  `rotate()` calls still work).
- **Retry policy.** Network failures and `5xx` responses are retried with
  exponential backoff (defaults: 1s → 2s → 4s, capped at 10s, 15s timeout
  per attempt). `401` responses are **not** retried — they fire `onAuthError`.
- **Offline-aware.** While `navigator.onLine` is false, rotations short-circuit
  and the next `online` event triggers one rotation if anything was queued.
  Otherwise the existing schedule resumes against the known expiry.
- **SSR-safe.** All browser APIs are guarded; rotation is a no-op on the server.

### Backend contract

The endpoint at `refreshPath` is expected to:

- Accept `POST` with `credentials: "include"` (httpOnly refresh-token cookie).
- Return **200** with a JSON body `{ "accessTokenExpiresAt": "<ISO8601>" }`
  on success. New cookies (refresh + access) should be set via `Set-Cookie`.
- Return **401** with `{ "error": "<code>" }` on failure, where `<code>` is
  one of: `token_missing`, `token_not_found`, `token_expired`, `token_reuse`,
  `family_revoked`, `absolute_timeout`. Use `errorCodeMap` if your backend
  emits different strings.

The `@theauth/core` package's `createSessionRefresher()` handler implements
this contract verbatim.

### Migrating from a hand-rolled refresh loop

If you have a bespoke refresher (e.g. `token-refresh-service.ts`):

1. Delete the in-app retry/queue/timer code.
2. Add `refreshPath` and `onAuthError` to your `<KavachProvider external>` config.
3. Optional: pass `onSessionRotated` to refetch your data layer.
4. Replace direct `triggerRefresh()` calls with `useRotateSession().rotate()`.

## Docs

[https://docs.theauth.com](https://docs.theauth.com)

## License

MIT
