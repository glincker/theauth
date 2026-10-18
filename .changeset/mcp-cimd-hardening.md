---
"@glinr/theauth": major
---

Client ID Metadata Documents (CIMD) are stricter, and some configurations that worked before now fail at startup.

- Turning on `clientIdMetadataDocuments.enabled` without a `consentPage` now throws when the MCP module is created. Before, any host could publish a client document and get an authorization code without the user approving anything. The authorize path also refuses a CIMD client with `CONSENT_REQUIRED` if no consent page is set.
- A `client_id` must be a canonical https URL on port 443 with a path. Hostnames that are IP literals, single labels, local or internal suffixes, or wildcard DNS services are refused before any fetch. A configurable `allowedHosts` and `deniedHosts` apply on top.
- The fetcher accepts only an exact 200 JSON response, never follows redirects, caps the body size and enforces one deadline across DNS, headers and body. A bounded limiter caps concurrent DNS lookups. Errors returned to callers are generic, and detail goes to `onEvent` and the logger.
- On runtimes without `node:dns` the `auto` resolver cannot check addresses: with no `allowedHosts` CIMD now fails closed, and with `allowedHosts` it warns once. `createDohResolver()` is a fetch-only resolver for edge runtimes. DNS rebinding cannot be fully ruled out in any mode, and only `allowedHosts` closes it. See `docs/mcp-client-id-metadata.mdx`.
- Fetched documents are validated strictly (the document repeats its own client_id, no shared secrets, no agent fields, exact redirect URIs, size limits). A refresh never undoes an admin's `disabled` state, `agentId` or block, and a bound client whose redirect URIs or auth method change is disabled. Freshness comes from the stored expiry, so isolates agree.
- New admin API `mcp.cimd` (block, unblock, list, refresh) and `mcp.describeClient()` for the consent page, with warnings such as a localhost or http redirect. A block on a URL revokes the client's tokens and adds their jtis to the denylist; a block on a host stops its clients and deletes tokens when the store can list them. Only an admin can bind a CIMD client to an agent.
- Per-host fetch limit (30 a minute), a cap of 1000 unconsented CIMD client rows with a daily sweep, case-sensitive client id matching, bounded JWKS and negative caches, and `enabled: false` no longer serves stored CIMD rows. Migration `0008` adds the snapshot columns and the `theauth_mcp_client_blocks` table.
- `registration: { enabled: false }` turns off dynamic client registration: the route returns 404 and `registration_endpoint` leaves the metadata.
