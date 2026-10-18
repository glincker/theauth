---
"@glinr/theauth": major
---

Security fix: `authorize(agentId)` now denies an agent whose `expiresAt` has passed, with code `agent_expired` and a denied audit row. Before, it checked only the stored `status`, so an elapsed agent kept passing until its status was flipped. Marked major because an agent that passed before can now fail. `authorizeByToken()`, `agent.validateToken()` and `policy.evaluate()` were already correct. See `docs/upgrading-to-2.mdx`.
