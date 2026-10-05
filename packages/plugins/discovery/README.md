# @glinr/theauth-plugin-discovery

A2A agent capability card discovery plugin for TheAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-plugin-discovery?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-plugin-discovery)

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
