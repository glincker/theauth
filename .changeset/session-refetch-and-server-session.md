---
"@glinr/theauth-client": minor
"@glinr/theauth-react": minor
"@glinr/theauth-vue": minor
"@glinr/theauth-svelte": minor
---

Session refetch, SSR hydration and real server calls in the client bindings.

Added: `refetch` options (window focus and tab visibility, reconnect, interval) and `hydrateSession(initial)` on `createSessionStore`, wired through the React provider (`managed` prop, `external.refetch`, `external.initialUser`), the Vue plugin, the Svelte client and the Solid helper. Triggers run only while something is subscribed, do nothing without a `window`, share one request across overlapping refreshes, are cancelable (`startAutoRefresh` returns `stop`, `destroy()` aborts), and never log or echo tokens.

Fixed: the Vue, Svelte and React managed bindings only read `localStorage` and never asked the server. They now confirm the session with `GET /auth/session`, and `signOut` calls `POST /auth/sign-out` after clearing local state, so the session is revoked server side. They also called `/auth/sign-in` and `/auth/sign-up`, which the core never served. The default routes are now `/auth/username/sign-in` and `/auth/username/sign-up` and the first argument is sent as `username`. Error bodies of the form `{ error: "text" }` are now read. External React mode keeps the current user when a refetch hits a network error.

Upgrade notes:

- `SessionStore.refresh()` now returns a promise and `SessionStore.signOut()` returns `Promise<StoreActionResult>`.
- If you served your own `/auth/sign-in` or `/auth/sign-up` routes for these bindings, set `signInPath`, `signUpPath` and `identifierField` (React: `managed`; Vue and Svelte: the plugin or client options).
- `@glinr/theauth-vue` and `@glinr/theauth-svelte` now depend on `@glinr/theauth-client`.
