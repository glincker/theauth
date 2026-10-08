---
"@glinr/theauth": minor
---

Harden the MCP authorization server and token families.

Behavior changes: `resource` is now required at the authorize and token endpoints and in `approveConsent`; `withMcpAuth` and `validateAccessToken` require `expectedAudience` (the module methods use the new `config.resource`); client secrets and stored access and refresh tokens are SHA-256 digests (legacy plaintext rows are still accepted and upgraded); refresh rotation detects reuse and revokes the token family; unknown or widened scopes on refresh return `invalid_scope`; authorization responses include `iss` (RFC 9207); `jwks_uri` is only advertised with asymmetric signing; registration no longer fetches `client_uri`; delegation reads the parent's permissions from storage, clamps the child expiry to the inbound chain, and honors inbound `maxDepth`; `TokenFamilyStore.consumeToken` claims tokens atomically.

New, opt in: ES256/EdDSA signing with `kid`, JWKS and key rotation; jti denylist; RFC 7009 revocation (`mcp.revoke`); Client ID Metadata Documents through an SSRF-safe fetcher.
