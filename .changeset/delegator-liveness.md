---
"@glinr/theauth": major
---

Security fix: a delegation link now lends permissions only while its delegator agent is live. Before, `getDelegatedPermissions`, `resolveLineage` and `resolveHookChain` checked the link but never the status or `expiresAt` of the delegating agent, so a revoked or expired intermediate agent kept lending to agents below it and still appeared as valid in the `beforeAuthorize` chain. `authorize()`, `authorizeByToken()`, `policy.evaluate()`, `explain()`, the simulator and the live MCP delegation check now agree. Marked major because chains that passed before can now fail. See `docs/upgrading-to-2.mdx`.
