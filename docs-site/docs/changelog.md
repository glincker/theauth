---
title: Changelog
description: What changed in each TheAuth release. Full release notes on GitHub.
---

# Changelog

This repo uses [Changesets](https://github.com/changesets/changesets). Per-package notes are generated automatically on release. The timeline below is the human-curated story of what each release actually delivered.

For the full raw record see [GitHub Releases](https://github.com/glincker/theauth/releases) and each `packages/*/CHANGELOG.md`.

## Timeline

### @glinr/theauth-nextjs-auth v0.1.0, May 2, 2026

New package. A focused Next.js (14/15/16) adapter for apps whose auth backend lives outside Next.js (Spring, Rails, Hono, Go, etc.). Distinct from `@glinr/theauth-nextjs` which bundles the agent-management runtime. This is the "I have a backend already, just give me session + cookies + refresh on the FE" path.

Ships eight server-side helpers (`createAuthConfig`, `getServerSession`, `refreshSession`, `fetchWithRefresh`, `graphqlWithRefresh`, `buildAuthHeaders`, `buildClientHeaders`, `createSignOutAction`) and an Edge-runtime-safe `withAuth()` middleware via a `/middleware` sub-export. Cookie prefix policy: `__Host-{prefix}-token` in production, plain names in development. 26 tests passing.

### v0.4.2, April 18, 2026

Fix on a missed barrel in 0.4.0. The ten new OAuth providers were added to `providers/index.ts` but the top-level `auth/index.ts` still pointed at the old nine-provider list, so `import { notion } from "@glinr/theauth/auth"` did not resolve. `auth/index.ts` now re-exports the whole barrel, so providers added in later releases pick themselves up automatically.

### v0.4.1, April 18, 2026

`@glinr/theauth/standards` shipped in 0.4.0 but was missing from the `exports` field in `package.json` and from the tsup build entries, which meant `import { AGENTIC_JWT_CLAIMS } from "@glinr/theauth/standards"` failed at resolve time. Both are fixed.

### v0.4.0, April 18, 2026

Four things shipped together.

- **Agentic JWT claim constants.** The two relevant IETF drafts (`draft-goswami-agentic-jwt-00` and `draft-liu-agent-operation-authorization-01`) are encoded as typed constants. Enabling the new `emitAgenticJwtClaims` config flag populates `agent_id`, `agent_type`, and `trust_tier` on every issued token. Off by default so existing deployments do not change shape on upgrade.
- **Ten OAuth providers promoted to first-class.** Notion, Spotify, Discord, Slack, Twitch, Reddit, Figma, Dropbox, Zoom, and Atlassian each ship as a named export with a typed factory, a `DEFAULT_X_SCOPES` constant, and a profile normalizer. Three files of boilerplate you no longer write per provider.
- **Audit export as Verifiable Credentials.** `exportAuditAsVC` in the new `@glinr/theauth/vc` subpath writes your audit log out as a W3C VC (`ldp_vc` or `jwt_vc`, individual events or a Verifiable Presentation). Useful for compliance exports that downstream auditors can verify without touching your database.
- **`@glinr/create-theauth-app` on npm.** `pnpm create theauth-app my-app` now scaffolds a working Next.js App Router template.

### v0.3.0, April 17, 2026

Two adapter additions and a schema defaults change.

- **`cookieAuth()` adapter.** Validates a JWT from an httpOnly cookie set by a non-Node backend (Go, Python, Rust). Use this when the canonical session already exists upstream and theauth is the read side.
- **`TheAuthProvider` external mode.** The React provider can now delegate auth to any external API. Same session semantics, different source of truth.
- **Feature-gated table creation.** The migrator only creates tables for features you turn on. Projects that do not use passkeys no longer get passkey tables.

### v0.2.x

See [GitHub Releases](https://github.com/glincker/theauth/releases) for the full history.
