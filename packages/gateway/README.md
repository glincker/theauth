# @kavachos/gateway

Standalone auth proxy that enforces KavachOS policies in front of any HTTP service.

[![npm](https://img.shields.io/npm/v/@kavachos/gateway?style=flat-square)](https://www.npmjs.com/package/@kavachos/gateway)

## Install

```bash
npm install @kavachos/gateway
```

## Usage

Create a gateway with route policies, then call `handle` on every incoming request.

```ts
import { createGateway, loadConfigFile } from '@kavachos/gateway';

const gateway = createGateway({
  kavachApiUrl: 'https://auth.yourapp.com',
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
const config = await loadConfigFile('./kavach-gateway.json');
const gateway = createGateway(config);
```

## Exports

- `createGateway` — creates a gateway instance
- `loadConfigFile` — loads gateway config from a JSON/YAML file
- `matchPolicy` — utility to test a request against a policy

## Docs

[https://docs.kavachos.com/gateway](https://docs.kavachos.com/gateway)

## License

MIT
