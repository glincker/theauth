# create-kavachos-app

## 0.2.0

### Minor Changes

- Add the `hono-mcp` template. Scaffolds a Hono server that mounts the KavachOS auth routes and the MCP OAuth 2.1 surface under `/api`, with `/tools/list` and `/tools/call/:name` behind `authorizeByToken` or MCP JWT validation. Complements the existing `next-saas` template with an agent-first starter.

  The `expo-mobile` template stays behind its placeholder.

## 0.1.0

### Minor Changes

- feat: v3 wave

  - Agentic JWT claim constants (`AGENTIC_JWT_CLAIMS`) from `draft-goswami-agentic-jwt-00` and `draft-liu-agent-operation-authorization-01`, behind a new `emitAgenticJwtClaims` config flag. Populates `agent_id`, `agent_type`, and `trust_tier` on issued tokens when on. Off by default.
  - Ten OAuth providers (Notion, Spotify, Discord, Slack, Twitch, Reddit, Figma, Dropbox, Zoom, Atlassian) promoted to first-class named exports with typed factories, `DEFAULT_X_SCOPES` constants, and profile normalisers.
  - `exportAuditAsVC` in `kavachos/vc` for compliance audit exports as W3C Verifiable Credentials (`ldp_vc` or `jwt_vc`, individual or Verifiable Presentation).
  - Initial `create-kavachos-app` scaffolder on npm with a Next.js App Router template.
