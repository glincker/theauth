# kavachos

## 0.4.2

### Patch Changes

- fix: re-export the 10 new OAuth provider factories from `kavachos/auth`

  The wave that added Notion, Spotify, Discord, Slack, Twitch, Reddit, Figma, Dropbox, Zoom, and Atlassian updated the OAuth `providers/index.ts` barrel but left the top-level `auth/index.ts` pointing at the old 9-provider list. Consumers could not import the new factories or their `DEFAULT_*_SCOPES` constants from `kavachos/auth`. Replaced the explicit list with `export *` so new providers picked up automatically in future releases too.

## 0.4.1

### Patch Changes

- fix: expose the `kavachos/standards` subpath

  The standards module shipped in 0.4.0 but was missing from `tsup.config.ts` entries and the `exports` field in `package.json`. Consumers can now `import { AGENTIC_JWT_CLAIMS } from "kavachos/standards"` as the docs describe.

## 0.4.0

### Minor Changes

- feat: v3 wave

  - Agentic JWT claim constants (`AGENTIC_JWT_CLAIMS`) from `draft-goswami-agentic-jwt-00` and `draft-liu-agent-operation-authorization-01`, behind a new `emitAgenticJwtClaims` config flag. Populates `agent_id`, `agent_type`, and `trust_tier` on issued tokens when on. Off by default.
  - Ten OAuth providers (Notion, Spotify, Discord, Slack, Twitch, Reddit, Figma, Dropbox, Zoom, Atlassian) promoted to first-class named exports with typed factories, `DEFAULT_X_SCOPES` constants, and profile normalisers.
  - `exportAuditAsVC` in `kavachos/vc` for compliance audit exports as W3C Verifiable Credentials (`ldp_vc` or `jwt_vc`, individual or Verifiable Presentation).
  - Initial `create-kavachos-app` scaffolder on npm with a Next.js App Router template.

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
