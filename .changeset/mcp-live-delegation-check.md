---
"@glinr/theauth": minor
---

MCP: new opt-in `delegationStore` config that re-checks a token's `act` delegation chain against live link records in `validateAccessToken`. A missing, revoked or expired link rejects the token with `INVALID_TOKEN`, so revoking a parent grant no longer leaves tokens minted down the chain valid until `exp`. Adds `createDbDelegationStore(db)` and the `McpDelegationStore` and `McpDelegationLink` types. Default behaviour is unchanged when not configured.
