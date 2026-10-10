# Branding notes

Internal copy reference. This file is not part of the published docs navigation.

## Positioning line

Auth where AI agents get their own identity, limited permissions and an audit trail, next to normal human sign in.

## One paragraph

Most auth libraries stop at human sign in. When an AI agent calls your API or an MCP server, it usually borrows a user's session or a shared key, and afterwards you cannot tell who did what. theAuth gives each agent its own identity and token, limited permissions granted by a human owner, delegation with a depth limit and an expiry, and an audit row for every decision. Human sign in and an OAuth 2.1 authorization server for MCP live in the same library.

## GitHub About text (under 120 characters)

Auth where AI agents get their own identity, limited permissions and an audit trail, next to human sign in.

## Facts that stay true until they change

- Version is 0.x. Not audited, not certified.
- MIT licensed. TypeScript SDK plus a Go SDK (theauth-go).
- Runs on Node, Bun, Deno and Cloudflare Workers.
- Core has four runtime dependencies: `drizzle-orm`, `jose`, `sql.js`, `zod`.
- MCP OAuth 2.1 authorization server included.
- Agent tokens start with `kv_`. The prefix predates the rename from Kavach and stays so issued tokens keep working.
- Name: TheAuth (formal), theAuth (prose and logo), theauth (code and npm).
- Contact: support@glinr.com. Community: GLINR Discord (shared server).

## Approved phrases

- "agents get their own identity, limited permissions and an audit trail"
- "next to normal human sign in"
- "delegation with a depth limit and an expiry"
- "an audit row for every decision"
- "MCP OAuth 2.1 server"
- "self-hostable, no hosted service required"
- "0.x, not independently audited"
- "17 OAuth providers with their own factories, plus a generic OIDC factory"

## Phrases to avoid

- "first-class" (as in "first-class providers" or "first-class agents"): say what it means instead
- "edge-native", "enterprise-grade", "battle-tested", "secure", "audited", "certified", "bank-grade"
- "three runtime dependencies" (it is four)
- "Better Auth alternative" in taglines (comparison belongs in the compare page)
- "Kavach" in user-facing copy, except where explaining the `kv_` prefix or the migration codemod
- "Used by" lists, demo URLs, anything implying production users we cannot name
- Em dashes, en dashes, and AI-ish words: seamless, robust, comprehensive, crucial, landscape, showcase
- `@theauth.com` addresses
