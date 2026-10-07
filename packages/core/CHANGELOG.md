# theauth

## 0.6.0

### Minor Changes

- 0fa5b1e: Remove the legacy KavachOS naming. The deprecated `Kavach*` and `createKavach` exports are gone: use `TheAuth*` and `createTheAuth`. Environment variables are now `THEAUTH_*`, webhook headers `X-TheAuth-*`, cookies and the default API route use `theauth`, and database tables are `theauth_*` (existing `kavach_*` tables are renamed in place by `createTables`, no data is lost). `Auth*` aliases remain deprecated.
- 9861742: Harden the SCIM 2.0 server. List endpoints now accept the full RFC 7644 filter grammar through a real parser, with operators eq, ne, co, sw, ew, gt, ge, lt, le and pr, the and, or and not combinators, parentheses and value path selectors, plus sortBy and sortOrder. PATCH supports path expressions with value filters such as emails[type eq "work"].value, rejects changes to immutable attributes and caps a request at 1000 operations. A new opt in Me endpoint resolves the caller through a resolveSelf callback, and the Bulk endpoint returns a spec compliant 501. Every successful provisioning write can now be recorded in the audit log by passing audit with an agent id. The Enterprise User extension is supported and advertised in the Schemas endpoint, and the repo gains an Okta example and a compatibility table.

### Patch Changes

- 960fe89: Delegation requests whose permissions are not a subset of the parent's now return HTTP 400 with error code `DELEGATION_PERMISSION_SUBSET` instead of a 500. Core throws a typed `DelegationError` (codes `DELEGATION_PERMISSION_SUBSET` and `DELEGATION_DEPTH_EXCEEDED`) and every REST adapter maps it to a 400 using that code.
- dfd31f9: Fix `ipAllowlist` denying every REST call. The permission engine now resolves the client IP from the request context first (what the framework adapters pass), then `request.ip`, so the allowlist and audit log agree.
- 5e53bdb: Fix plugin endpoint rate limit windows in the anonymous, device, SIWE, and OAuth proxy plugins. They declared `rateLimit.window` in milliseconds while the plugin router reads it as seconds, so a 60_000 window lasted about 16 hours. The window is now in seconds, and the `PluginEndpoint` type documents the unit.

## 0.5.0

### Minor Changes

- TheAuth is now the canonical naming across the SDK (`TheAuthClient`,
  `TheAuthProvider`, `TheAuthError`, `createTheAuth`, and per-adapter
  equivalents like `theAuthExpress`/`theAuthHono`). This resolves a
  three-way naming collision: an earlier pass renamed `Kavach*` to `Auth*`,
  this pass supersedes that with `TheAuth*` as canonical.

  Non-breaking. Both `Auth*` and `Kavach*` names remain as deprecated
  aliases pointing at the same implementation and will keep working until
  a future major version. No behavior changed, only naming.

  Also fixes two adapters (`express`, `hono`) that were missed by the
  earlier `Auth*` rename entirely and still only exported `kavach`-prefixed
  names.

## 0.4.2

### Patch Changes

- fix: re-export the 10 new OAuth provider factories from `@glinr/theauth/auth`

  The wave that added Notion, Spotify, Discord, Slack, Twitch, Reddit, Figma, Dropbox, Zoom, and Atlassian updated the OAuth `providers/index.ts` barrel but left the top-level `auth/index.ts` pointing at the old 9-provider list. Consumers could not import the new factories or their `DEFAULT_*_SCOPES` constants from `@glinr/theauth/auth`. Replaced the explicit list with `export *` so new providers picked up automatically in future releases too.

## 0.4.1

### Patch Changes

- fix: expose the `@glinr/theauth/standards` subpath

  The standards module shipped in 0.4.0 but was missing from `tsup.config.ts` entries and the `exports` field in `package.json`. Consumers can now `import { AGENTIC_JWT_CLAIMS } from "@glinr/theauth/standards"` as the docs describe.

## 0.4.0

### Minor Changes

- feat: v3 wave

  - Agentic JWT claim constants (`AGENTIC_JWT_CLAIMS`) from `draft-goswami-agentic-jwt-00` and `draft-liu-agent-operation-authorization-01`, behind a new `emitAgenticJwtClaims` config flag. Populates `agent_id`, `agent_type`, and `trust_tier` on issued tokens when on. Off by default.
  - Ten OAuth providers (Notion, Spotify, Discord, Slack, Twitch, Reddit, Figma, Dropbox, Zoom, Atlassian) promoted to first-class named exports with typed factories, `DEFAULT_X_SCOPES` constants, and profile normalisers.
  - `exportAuditAsVC` in `@glinr/theauth/vc` for compliance audit exports as W3C Verifiable Credentials (`ldp_vc` or `jwt_vc`, individual or Verifiable Presentation).
  - Initial `@glinr/create-theauth-app` scaffolder on npm with a Next.js App Router template.

## 0.3.0

### Minor Changes

- feat: add cookieAuth adapter and external auth mode

  - `cookieAuth()` adapter: validates JWT from httpOnly cookies (for Go/Python/etc backends)
  - `KavachProvider` external mode: delegate auth to any external API
  - Feature-gated table creation: only creates tables for features you enable

## 0.1.0

### Minor Changes

- 94804ec: Launch release: promote core and primary client-facing packages to the 0.1 line.

  Highlights:

  - Stabilize package exports and build artifacts for launch.
  - Ship improved CLI version handling and launch docs.
  - Keep adapters/plugins/dashboard on existing release tracks for a separate coordinated versioning pass.
