---
"@glinr/theauth": patch
---

Fix a revocation bypass in the unreleased 2.0 MCP revocation work. No public release is affected, because the revocation binding was never released.

The token endpoint now checks the revocation store, live, before minting from a refresh token or an authorization code: the token's `jti`, the subject (sign out everywhere, ban, delete), the client (CIMD block) and the bound agent. A hit is refused with `invalid_grant` (and kills the refresh family); a store error fails closed with `server_error`. When refresh token reuse is detected, or a refresh token is revoked through `/mcp/revoke`, the access tokens already minted from that family are now denylisted by `jti` (with their own expiry so the rows can be pruned), so a thief's access token stops working at once. `revokeTokenFamily` store functions may return the family's `{ jti, expiresAt }` list; the database store does.
