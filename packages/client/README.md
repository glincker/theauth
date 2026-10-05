# @glinr/theauth-client

Zero-dependency TypeScript REST client for the TheAuth API.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-client?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-client)

## Install

```bash
npm install @glinr/@glinr/theauth-client
```

## Usage

Works in Node.js, Cloudflare Workers, Deno, and the browser.

```ts
import { createKavachClient, KavachApiError } from '@glinr/theauth-client';

const kavach = createKavachClient({
  apiUrl: 'https://auth.yourapp.com',
  tenantId: 'your-tenant-id',
  apiKey: process.env.KAVACH_API_KEY,
});

// Authorize a token
const result = await kavach.authorize({ token: incomingToken, requiredPermissions: ['read:data'] });

if (!result.ok) {
  throw new Error('Unauthorized');
}

// Manage agents
const agent = await kavach.createAgent({ name: 'my-bot', permissions: ['read:data'] });
const agents = await kavach.listAgents();

// Delegate permissions
await kavach.delegate({ agentId: agent.id, permissions: ['read:data'], expiresIn: '1h' });
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

## Error handling

```ts
try {
  await kavach.authorize({ token });
} catch (err) {
  if (err instanceof KavachApiError) {
    console.error(err.status, err.body.code);
  }
}
```

## Docs

[https://docs.theauth.dev/client](https://docs.theauth.dev/client)

## Community

[![Discord](https://img.shields.io/discord/829168897080557579?style=flat-square&logo=discord&logoColor=white&label=discord&color=5865F2)](https://discord.gg/Ar5pcaZB99)

Questions and help in the `#theauth` forum on the [GLINR Discord](https://discord.gg/Ar5pcaZB99).

## License

MIT
