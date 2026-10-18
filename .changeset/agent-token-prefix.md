---
"@glinr/theauth": minor
"@glinr/theauth-mcp": minor
---

Agent tokens now start with `ta_` instead of `kv_` (a leftover of the old kavachOS name). The format is otherwise unchanged: `ta_` plus 43 base64url characters (32 random bytes), SHA-256 hashed at rest.

Compatible migration: tokens already issued with `kv_` keep validating. Lookups are by token hash, so no stored data is rewritten and no database migration is needed. `agent.rotate` issues a `ta_` token for a legacy agent and retires the old one. A bearer string with neither prefix is now rejected before any database lookup.

Added `AGENT_TOKEN_PREFIX`, `LEGACY_AGENT_TOKEN_PREFIXES`, `isAgentToken` and `agentTokenLookupPrefix` to `@glinr/theauth`. The MCP `inspect_token` tool recognizes both prefixes. If you match agent tokens by prefix in your own code (proxies, log scrubbers, secret scanners), accept both `ta_` and `kv_`. "Token format" in `docs/agents.mdx` has a scanning regex for GitHub secret scanning and gitleaks.
