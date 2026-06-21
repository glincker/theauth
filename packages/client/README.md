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

[https://docs.theauth.com/client](https://docs.theauth.com/client)

## License

MIT
