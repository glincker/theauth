---
"@glinr/theauth": minor
"@glinr/theauth-cli": minor
---

Add a permission simulator. `createSimulator()` answers "what would this agent be allowed to do?" with a decision (`allow`, `deny`, `needs_approval`), reasons and a step by step trace, without writing audit rows or touching rate and budget state. It supports what-if overrides (extra permissions, other delegation chains, a budget cost), `simulateMany` for agent by action matrices, and `effectivePermissions`. The opt-in `simulator()` plugin mounts the admin-only `POST /agents/:id/simulate`, and the CLI gains `theauth simulate` and `theauth permissions`. Resource matching and constraint evaluation moved into shared helpers in `policy/abac.ts` so `authorize()` and the simulator run the same code; `authorize()` behavior is unchanged.
