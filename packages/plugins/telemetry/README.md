# @glinr/theauth-plugin-telemetry

OpenTelemetry integration plugin for theAuth - converts auth events into OTel spans.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-plugin-telemetry?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-plugin-telemetry)

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Install

```bash
npm install @glinr/theauth-plugin-telemetry
```

## Usage

```typescript
import { createTelemetryModule } from "@glinr/theauth-plugin-telemetry";

const telemetry = await createTelemetryModule({
  theauth, // TheAuth core instance
  // Configure exporter and sampling
});
```

## Exports

- `createTelemetryModule`: initialize telemetry
- `TelemetryConfig`, `TelemetrySpan`: TypeScript types

## Docs

[https://go.theauth.dev](https://go.theauth.dev)

## License

MIT
