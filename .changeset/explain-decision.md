---
"@glinr/theauth": minor
---

Add `theauth.explain(agentId, action, resource, options?)`. It mirrors `authorize()` and returns the decision code, the matched grant (own rule or the delegation link that carried it), the constraint checks, the delegation chain and the `beforeAuthorize` outcome, with no audit rows, no rate counter changes, no approval spend and no caching. `beforeAuthorize` only runs with `runHooks: true`, and receives `dryRun: true` and `source: "explain"`. Evaluation is shared with the simulator through `src/simulator/evaluate-set.ts`.
