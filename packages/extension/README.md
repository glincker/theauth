# @glinr/theauth-extension

OAuth 2.1 sign in for Manifest V3 browser extensions. Authorization code with PKCE (S256), refresh that survives service worker restarts, optional DPoP, and a message bridge so content scripts never see the refresh token.

Zero runtime dependencies. DPoP uses `@glinr/theauth-client` as an optional peer.

## Install

```bash
pnpm add @glinr/theauth-extension
```

Manifest permissions: `identity` and `storage`. Register `chrome.identity.getRedirectURL()` as a redirect URI on a public OAuth client.

## Use

```ts
// background.ts
import { createExtensionAuth, exposeAuthToBackground } from "@glinr/theauth-extension";

const auth = createExtensionAuth({
  issuer: "https://auth.example.com",
  clientId: "YOUR_CLIENT_ID",
  scopes: ["openid", "offline_access"],
  encryptRefreshToken: true,
});
exposeAuthToBackground(auth);
```

```ts
// popup.ts or content-script.ts
import { createAuthClient } from "@glinr/theauth-extension";

const auth = createAuthClient();
const token = await auth.getAccessToken();
```

## API

- `createExtensionAuth(options)` returns `{ signIn, getAccessToken, getSession, signOut, onChange, fetch }`.
- `exposeAuthToBackground(auth, { runtime?, allowedExtensionIds?, senderFilter? })` returns a function that removes its listeners.
- `createAuthClient({ runtime?, extensionId? })` returns `{ getAccessToken, getSession, signIn, signOut }`.
- `ExtensionAuthError` with codes `user_cancelled`, `state_mismatch`, `discovery_failed`, `authorization_failed`, `token_exchange_failed`, `refresh_failed`, `not_signed_in`, `invalid_config`, `message_rejected`.

Extension storage is readable by the extension's own code. `encryptRefreshToken` is defence in depth, not a vault.

Full guide: [docs/browser-extension.mdx](../../docs/browser-extension.mdx). Example: [examples/browser-extension](../../examples/browser-extension).

## License

MIT
