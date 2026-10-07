# @glinr/theauth-gateway

Standalone auth proxy that enforces TheAuth policies in front of any HTTP service.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-gateway?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-gateway)

## Install

```bash
npm install @glinr/theauth-gateway
```

## Usage

Create a gateway with route policies, then call `handle` on every incoming request.

```ts
import { createGateway, loadConfigFile } from '@glinr/theauth-gateway';

const gateway = createGateway({
  theAuthApiUrl: 'https://auth.yourapp.com',
  tenantId: 'your-tenant-id',
  upstream: 'http://localhost:3001',
  policies: [
    {
      match: { path: '/api/**', methods: ['GET', 'POST'] },
      require: { permissions: ['api:access'] },
      rateLimit: { requests: 100, windowMs: 60_000 },
    },
  ],
});

// Node HTTP server
import { createServer } from 'http';
createServer((req, res) => gateway.handle(req, res)).listen(8080);
```

### File-based config

```ts
const config = await loadConfigFile('./theauth-gateway.json');
const gateway = createGateway(config);
```

## Exports

- `createGateway`: creates a gateway instance
- `loadConfigFile`: loads gateway config from a JSON/YAML file
- `matchPolicy`: utility to test a request against a policy

## Docs

[https://docs.theauth.dev/gateway](https://docs.theauth.dev/gateway)

## Community

[![Discord](https://img.shields.io/discord/829168897080557579?style=flat-square&logo=discord&logoColor=white&label=discord&color=5865F2)](https://discord.gg/Ar5pcaZB99)

Questions and help in the `#theauth` forum on the [GLINR Discord](https://discord.gg/Ar5pcaZB99).

## License

MIT
