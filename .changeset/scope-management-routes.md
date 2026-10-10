---
"@glinr/theauth": patch
"@glinr/theauth-hono": patch
"@glinr/theauth-express": patch
---

Scope management routes to the signed in owner when the default guard is used. With the default session resolver, `/agents`, `/delegations`, `/audit`, `/dashboard` and `POST /authorize` only act on the caller's own agents, delegations and audit rows, and `POST /agents` requires `ownerId` to be the caller. A custom `authenticate` resolver behaves as before. Core adds `guard.resolve()` and the `AdapterScope` helper so the other adapters can adopt the same checks, and `audit.export()` accepts a `userId` filter.
