---
"@glinr/theauth": minor
---

`agent.revoke()` now revokes every active delegation chain where the agent is the source or the target, and the chains downstream of them. It returns the revoked chain ids as `revokedDelegations` and writes one `agent.cascade.revoked` audit row that joins the hash chain.
