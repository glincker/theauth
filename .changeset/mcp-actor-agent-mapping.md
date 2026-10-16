---
"@glinr/theauth": minor
---

Added `resolveActorAgentId` and `allowUnmappedActors` to the MCP config. The live delegation check can now map each actor in a token's `act` chain (and the token subject) to the agent id used in delegation records before it looks up the link, so the built-in `createDbDelegationStore` works when token exchange sets `act.sub` to a user or client id. An actor the mapper returns `undefined` for rejects the token with `INVALID_TOKEN` ("unmapped actor") unless `allowUnmappedActors` is true, and a mapper that throws always rejects. Without a mapper nothing changes. `checkLiveDelegation` now takes an options object as its fourth argument in place of the `now` date.
