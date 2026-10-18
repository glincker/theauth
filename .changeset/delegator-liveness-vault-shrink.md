---
"@glinr/theauth": major
---

Security fix: token vault use and policy-shrink grants now honor delegator liveness. A downstream agent can no longer use a vault credential through a consent whose delegation chain includes a revoked or expired agent, and `loadGrants`/`analyzeUsage` no longer count grants from dead links. Also, an active delegator whose inbound links are all dead keeps the onward links that grant only permissions it holds directly (before, they died with the inbound chain). Marked major because vault access that succeeded before can now be refused. See `docs/upgrading-to-2.mdx`.
