---
"@glinr/theauth": minor
"@glinr/theauth-plugin-telemetry": minor
"@glinr/theauth-dashboard": minor
---

Add observability. `observability.onDecision(event)` receives one typed event per `authorize`, `authorizeByToken` and `policy.evaluate` decision (agent, owner, action, resource, decision, code, duration, cache hit, delegation depth, hook outcome, guard). It runs in a queued microtask, so it never delays or changes a decision, and a throwing listener is swallowed and counted (`theauth.observability.stats()`). Events carry no tokens and no raw arguments, and `observability.redactResource` rewrites the resource string. A new `logger` option (`debug`, `info`, `warn`, `error`, no-op by default) receives hook timeout and listener failure warnings.

`@glinr/theauth-plugin-telemetry` adds `theauthOtel({ tracer, meter })`: the `theauth.decisions` counter, the `theauth.decision.duration` histogram, one span per decision, and span events for hook timeouts. No new dependency.

The dashboard audit page gains a Code column, a code filter, and a Why drawer that calls `POST /explain`.

Upgrade notes: additive, nothing changes unless you set `observability` or `logger`. The dashboard sends `codes` to your audit endpoint and calls `/api/explain`, so mount the HTTP handler at `/api`. See docs/observability.mdx.
