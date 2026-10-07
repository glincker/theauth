# @glinr/create-theauth-app

## 0.3.0

### Minor Changes

- 0fa5b1e: Remove the legacy KavachOS naming. The deprecated `Kavach*` and `createKavach` exports are gone: use `TheAuth*` and `createTheAuth`. Environment variables are now `THEAUTH_*`, webhook headers `X-TheAuth-*`, cookies and the default API route use `theauth`, and database tables are `theauth_*` (existing `kavach_*` tables are renamed in place by `createTables`, no data is lost). `Auth*` aliases remain deprecated.

## 0.2.0

### Minor Changes

- Add the `hono-mcp` template. Scaffolds a Hono server that mounts the TheAuth auth routes and the MCP OAuth 2.1 surface under `/api`, with `/tools/list` and `/tools/call/:name` behind `authorizeByToken` or MCP JWT validation. Complements the existing `next-saas` template with an agent-first starter.

  The `expo-mobile` template stays behind its placeholder.

## 0.1.0

### Minor Changes

- feat: v3 wave

  - Agentic JWT claim constants (`AGENTIC_JWT_CLAIMS`) from `draft-goswami-agentic-jwt-00` and `draft-liu-agent-operation-authorization-01`, behind a new `emitAgenticJwtClaims` config flag. Populates `agent_id`, `agent_type`, and `trust_tier` on issued tokens when on. Off by default.
  - Ten OAuth providers (Notion, Spotify, Discord, Slack, Twitch, Reddit, Figma, Dropbox, Zoom, Atlassian) promoted to first-class named exports with typed factories, `DEFAULT_X_SCOPES` constants, and profile normalisers.
  - `exportAuditAsVC` in `@glinr/theauth/vc` for compliance audit exports as W3C Verifiable Credentials (`ldp_vc` or `jwt_vc`, individual or Verifiable Presentation).
  - Initial `@glinr/create-theauth-app` scaffolder on npm with a Next.js App Router template.
