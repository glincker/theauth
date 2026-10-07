# @glinr/theauth-client

Zero-dependency TypeScript REST client for the theAuth API.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-client?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-client)

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Install

```bash
npm install @glinr/theauth-client
```

## Usage

Works in Node.js, Cloudflare Workers, Deno, and the browser.

```ts
import { createTheAuthClient, TheAuthApiError } from '@glinr/theauth-client';

const theauth = createTheAuthClient({
  apiUrl: 'https://auth.yourapp.com',
  tenantId: 'your-tenant-id',
  apiKey: process.env.THEAUTH_API_KEY,
});

// Authorize a token
const result = await theauth.authorize({ token: incomingToken, requiredPermissions: ['read:data'] });

if (!result.ok) {
  throw new Error('Unauthorized');
}

// Manage agents
const agent = await theauth.createAgent({ name: 'my-bot', permissions: ['read:data'] });
const agents = await theauth.listAgents();

// Delegate permissions
await theauth.delegate({ agentId: agent.id, permissions: ['read:data'], expiresIn: '1h' });
```

## theauth-go client

A typed client for servers built on `theauth-go` (default mount `/auth`). Every call returns `{ success, data }` or `{ success: false, error: { code, message, status, retryAfter? } }` and never throws.

```ts
import { createTheAuthGoClient } from "@glinr/theauth-client";

const auth = createTheAuthGoClient({ baseUrl: "https://api.example.com", basePath: "/auth" });

const res = await auth.login({ email, password });
if (res.success && res.data.status === "mfa_required") {
  await auth.totp.verify(code);
}

await auth.passkeys.register("Work laptop");
await auth.passkeys.login();
const { data: user } = await auth.session.get();
```

Requests send `credentials: "include"` so the session cookie works cross-origin. Pass `fetch`, `headers` or `credentials` to override. Routes the server does not expose yet are listed in `MISSING.md`.

Further namespaces: `session.list/revoke/revokeOthers`, `changePassword`, `stepUp.verify/passkey`, `apiTokens.list/mint/revoke/current/revokeCurrent`, `agents.list/register/revoke`, `delegations.list/grant/revoke`, `device.code/token/poll/info/approve/deny`, `bootstrap.status`, `totp.status/regenerateRecoveryCodes`, `passkeys.rename`, and `signup({ setupToken })` (sent as `X-Setup-Token`).

```ts
import { isRecentAuthRequired, isThrottleError } from "@glinr/theauth-client";

const r = await auth.apiTokens.revoke(id);
if (!r.success && isRecentAuthRequired(r.error)) {
  await auth.stepUp.verify({ method: "password", password });
}
if (!r.success && isThrottleError(r.error)) {
  wait(r.error.retryAfter); // rate_limited or account_locked, seconds from Retry-After
}

const dc = await auth.device.code({ clientName: "my-cli" });
const token = await auth.device.poll({ deviceCode: dc.data.deviceCode, interval: dc.data.interval, expiresIn: dc.data.expiresIn });
```

`device.poll` waits `interval` seconds between attempts, adds 5 on `slow_down`, and stops on any other error (`access_denied`, `expired_token`). Device endpoints use the RFC 8628 `{ error, error_description }` body; the client maps it to the same `code` and `message` fields.

### Bearer mode and agents

```ts
const auth = createTheAuthGoClient({ getToken: () => process.env.THEAUTH_TOKEN });
const me = await auth.apiTokens.current(); // GET /auth/tokens/current, bearer-only
if (!me.success && isBearerRequired(me.error)) {
  // a cookie session called a bearer-only route (403 auth.bearer_required)
}
await auth.apiTokens.revokeCurrent();
```

`agents` and `delegations` call `/auth/account/*`, which the server mounts only with AccountUX enabled and a cookie session.

### Route drift guard

`routes.manifest.json` lists the Go routes the client targets, with the theauth-go commit it was curated from. `tests/route-drift.test.ts` fails when a client method hits a path or verb that is not in it. `tools/route-manifest` (repo root) is a standard-library Go program that scans a theauth-go checkout for chi registrations so the Go repo can regenerate the file in CI.

## Error handling

```ts
try {
  await theauth.authorize({ token });
} catch (err) {
  if (err instanceof TheAuthApiError) {
    console.error(err.status, err.body.code);
  }
}
```

## Docs

[https://docs.theauth.dev/client-sdk](https://docs.theauth.dev/client-sdk)

## Community

[![Discord](https://img.shields.io/discord/829168897080557579?style=flat-square&logo=discord&logoColor=white&label=discord&color=5865F2)](https://discord.gg/Ar5pcaZB99)

Questions and help in the `#theauth` forum on the [GLINR Discord](https://discord.gg/Ar5pcaZB99).

## License

MIT
