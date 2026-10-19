# @glinr/theauth-plugin-telemetry

## 4.1.0

### Minor Changes

- a561306: Add observability. `observability.onDecision(event)` receives one typed event per `authorize`, `authorizeByToken` and `policy.evaluate` decision (agent, owner, action, resource, decision, code, duration, cache hit, delegation depth, hook outcome, guard). It runs in a queued microtask, so it never delays or changes a decision, and a throwing listener is swallowed and counted (`theauth.observability.stats()`). Events carry no tokens and no raw arguments, and `observability.redactResource` rewrites the resource string. A new `logger` option (`debug`, `info`, `warn`, `error`, no-op by default) receives hook timeout and listener failure warnings.

  `@glinr/theauth-plugin-telemetry` adds `theauthOtel({ tracer, meter })`: the `theauth.decisions` counter, the `theauth.decision.duration` histogram, one span per decision, and span events for hook timeouts. No new dependency.

  The dashboard audit page gains a Code column, a code filter, and a Why drawer that calls `POST /explain`.

  Upgrade notes: additive, nothing changes unless you set `observability` or `logger`. The dashboard sends `codes` to your audit endpoint and calls `/api/explain`, so mount the HTTP handler at `/api`. See docs/observability.mdx.

## 4.0.0

### Minor Changes

- 0fa5b1e: Remove the legacy KavachOS naming. The deprecated `Kavach*` and `createKavach` exports are gone: use `TheAuth*` and `createTheAuth`. Environment variables are now `THEAUTH_*`, webhook headers `X-TheAuth-*`, cookies and the default API route use `theauth`, and database tables are `theauth_*` (existing `kavach_*` tables are renamed in place by `createTables`, no data is lost). `Auth*` aliases remain deprecated.

### Patch Changes

- Updated dependencies [960fe89]
- Updated dependencies [dfd31f9]
- Updated dependencies [5e53bdb]
- Updated dependencies [0fa5b1e]
- Updated dependencies [9861742]
  - @glinr/theauth@0.6.0

## 3.0.3

### Patch Changes

- Updated dependencies
  - @glinr/theauth@0.5.0

## 3.0.2

### Patch Changes

- Updated dependencies
  - theauth@0.4.2

## 3.0.1

### Patch Changes

- Updated dependencies
  - theauth@0.4.1

## 3.0.0

### Patch Changes

- Updated dependencies
  - theauth@0.4.0

## 2.0.0

### Patch Changes

- Updated dependencies
  - theauth@0.3.0

## 1.0.0

### Major Changes

- 94804ec: Launch wave B: explicit major alignment for adapters/plugins after core moves to the 0.1 line.

  Why major:

  - These packages are pre-1.0 and depend on core package version semantics.
  - Core 0.0.x -> 0.1.x is treated as breaking for dependent package versioning.

  Operator notes:

  - Publish this wave separately from the core/client 0.1.0 wave.
  - Keep `@glinr/theauth-dashboard` on its independent track.

### Patch Changes

- Updated dependencies [94804ec]
  - theauth@0.1.0
