---
"@glinr/theauth": minor
"@glinr/theauth-expo": minor
---

Native app social sign-in. The oauth plugin takes `mobile: { redirectUris }` and adds a PKCE code exchange at `POST /auth/oauth/mobile/exchange`, so a session token is never placed in a redirect URL. `@glinr/theauth-expo` gains `signInWithProvider` and `useSocialSignIn`, `createSecureStoreStorage`, and an `appState` option that refreshes the session when the app returns to the foreground. The oauth plugin now also creates the `theauth_one_time_tokens` table.
