---
"@glinr/theauth": minor
"@glinr/theauth-cli": minor
---

`/mcp/revoke` answers 503 with `Retry-After` and `temporarily_unavailable` (RFC 7009) when the revocation store cannot record a revoke, instead of a 500; the freshness cache is still dropped and unknown tokens still get 200. `mcp.cimd.block` now writes a `client` revocation row, so the blocked client's tokens are refused at once in live mode. The optional `rememberMe` choice is plumbed through username sign in, magic link verify, passkey verify, the OAuth callback (via `?rememberMe` on authorize) and the sign in gate completions; absent means no change. `theauth doctor` gains `--fail-on info|warn|fail` and the `audit.secrets_table_collision` rule.
