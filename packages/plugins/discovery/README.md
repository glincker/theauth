# @glinr/theauth-plugin-discovery

[npm](https://www.npmjs.com/package/@glinr/theauth-plugin-discovery) · [Source](https://github.com/glincker/theauth/tree/main/packages/plugins/discovery) · [Docs](https://docs.theauth.dev/a2a) · [All packages](https://github.com/glincker/theauth#packages)

A2A agent capability card discovery plugin for theAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-plugin-discovery?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-plugin-discovery)

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Install

```bash
npm install @glinr/theauth-plugin-discovery
```

## Usage

```typescript
import { createDiscoveryModule } from "@glinr/theauth-plugin-discovery";

const discovery = await createDiscoveryModule({
  theauth, // TheAuth core instance
});
```

## Exports

- `createDiscoveryModule`: initialize capability discovery
- `AgentCard`, `AgentCapability`: TypeScript types

## Docs

[https://go.theauth.dev](https://go.theauth.dev)

## License

MIT
