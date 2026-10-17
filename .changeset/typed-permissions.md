---
"@glinr/theauth": minor
---

Add opt-in typed permissions. `definePermissions({ "mcp:github:*": ["read", "write"] })` declares a catalog, and passing it as `createTheAuth({ permissions })` returns a `TypedTheAuth<C>` where `authorize`, `authorizeByToken`, `agent.create`, `agent.update` and `delegate` only accept declared resources and actions, so typos are compile errors. Instances created without `permissions` are unchanged. The catalog is not enforced at runtime. Also adds `TheAuthConfig.permissions`.
