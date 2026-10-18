# @glinr/theauth-plugin-telemetry

[npm](https://www.npmjs.com/package/@glinr/theauth-plugin-telemetry) · [Source](https://github.com/glincker/theauth/tree/main/packages/plugins/telemetry) · [All packages](https://github.com/glincker/theauth#packages)

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

### OpenTelemetry mapping for decision events

```typescript
import { metrics, trace } from "@opentelemetry/api";
import { theauthOtel } from "@glinr/theauth-plugin-telemetry";

const theauth = await createTheAuth({
  // ...
  ...theauthOtel({ tracer: trace.getTracer("theauth"), meter: metrics.getMeter("theauth") }),
});
```

Emits the `theauth.decisions` counter and `theauth.decision.duration` histogram (ms), plus one span per decision with hook timeout events. No `@opentelemetry` dependency. See [observability](https://docs.theauth.dev/observability).

## Exports

- `createTelemetryModule`: initialize telemetry
- `theauthOtel`, `OTEL_NAMES`: decision events to OpenTelemetry spans and metrics
- `TelemetryConfig`, `TelemetrySpan`, `TheAuthOtelOptions`: TypeScript types

## Docs

[https://go.theauth.dev](https://go.theauth.dev)

## License

MIT

<!-- theauth:links -->
## Learn more

- [Plugins](https://docs.theauth.dev/plugins)
- [All packages](https://github.com/glincker/theauth#packages)
- [GitHub Discussions](https://github.com/glincker/theauth/discussions) for questions
- [Report a security issue](https://github.com/glincker/theauth/blob/main/SECURITY.md)
