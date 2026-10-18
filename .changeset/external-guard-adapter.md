---
"@glinr/theauth": minor
---

Add `guardHook` and `composeBeforeAuthorize`, the external guard adapter contract. A guard such as HOL Guard implements `ExternalGuard.check(input, signal)`, receives the agent, request, full delegation chain, source, ip and `dryRun` (never the token), and returns a verdict. `guardHook` registers it through `beforeAuthorize` with the hook timeout and default deny; `composeBeforeAuthorize` combines several hooks with deny-overrides.
