---
"@glinr/theauth": patch
---

Close the DNS rebinding race in the client metadata document fetcher on Node and Bun. `safeFetchJson` now connects through `node:https` (loaded by a guarded dynamic import) pinned to the addresses it already vetted, so the name is never resolved a second time. Each address is vetted again at connect, one non-public address in a multi-address answer refuses the whole answer, TLS still validates the original hostname, keep-alive is off, and `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` are not used on that path. Workers, Deno, a custom `fetchImpl` and `pinnedConnect: "off"` keep the `fetch` path and the documented residual risk. New options: `pinnedConnect` and the test-only `caForTests`.
