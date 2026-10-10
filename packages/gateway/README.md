# @glinr/theauth-gateway

[npm](https://www.npmjs.com/package/@glinr/theauth-gateway) · [Source](https://github.com/glincker/theauth/tree/main/packages/gateway) · [Docs](https://docs.theauth.dev/gateway) · [All packages](https://github.com/glincker/theauth#packages)

Standalone auth proxy that enforces theAuth policies in front of any HTTP service.

Protect any MCP server with OAuth 2.1: run the gateway in front of it, and MCP clients authenticate against the gateway before a request reaches your server.

```bash
npx @glinr/theauth-gateway --upstream http://localhost:8080 --port 3000
```

Point your MCP client at the gateway instead of the upstream server. The examples below assume your server serves MCP at `/mcp`; use your own path.

Claude Code:

```bash
claude mcp add --transport http my-server http://localhost:3000/mcp
```

Cursor (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "my-server": {
      "url": "http://localhost:3000/mcp"
    }
  }
}
```

Claude Desktop (`claude_desktop_config.json`, using the `mcp-remote` bridge):

```json
{
  "mcpServers": {
    "my-server": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://localhost:3000/mcp"]
    }
  }
}
```

[![npm](https://img.shields.io/npm/v/@glinr/theauth-gateway?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-gateway)

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

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

### Behind a proxy

By default the gateway trusts no forwarded headers (`X-Forwarded-For`, `X-Real-IP`
and similar are ignored), so the client IP is unknown. Without an IP,
`ipAllowlist` constraints always deny and per client rate limits fall back to a
request fingerprint. If the gateway runs behind a reverse proxy or CDN, tell it
how to find the client IP with a `trustedProxy` section.

One reverse proxy that appends to `X-Forwarded-For`:

```json
{
  "upstream": "http://localhost:8080",
  "trustedProxy": { "trustedProxyCount": 1 }
}
```

Cloudflare, which sets a single header at its edge:

```json
{
  "upstream": "http://localhost:8080",
  "trustedProxy": { "trustedHeader": "cf-connecting-ip" }
}
```

- `trustedProxyCount`: non negative integer, the number of proxies you operate in
  front of the gateway. Default `0`.
- `trustedHeader`: header name (lowercased on load). Takes precedence over
  `trustedProxyCount`.

The CLI accepts the same settings as flags, which override the file:
`--trusted-proxy-count 1` or `--trusted-header cf-connecting-ip`.

Warning: set this only when the gateway is reachable solely through that proxy.
If clients can reach the gateway directly, they can send the header themselves
and choose their own IP.

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
