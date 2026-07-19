# Changelog

This repo uses [Changesets](https://github.com/changesets/changesets). Per-package notes are generated automatically on release. The timeline below is the human-curated story of what each release actually delivered, pulled from those per-package changelogs and commit history.

For the full raw record see [GitHub Releases](https://github.com/glincker/theauth/releases) and each `packages/*/CHANGELOG.md`.

## Timeline

### v0.5.0 (upcoming), June 2026 -- Kavach* to TheAuth* rename

No breaking change. All `Kavach*` exported identifiers now have `TheAuth*` canonical equivalents. Along the way the project also considered `Auth*` as an intermediate name; that idea was dropped in favor of `TheAuth*`, so `Auth*` ships only as a second deprecated alias, never as the primary name. Both `Auth*` and `Kavach*` are still exported as `@deprecated` aliases and will continue to work until a future major version, when they will be removed.

New canonical names added across all packages:

- `createTheAuth` / `TheAuth` / `TheAuthConfig` / `TheAuthInstance` (core)
- `TheAuthError` / `TheAuthHooks` / `TheAuthPlugin` (core internals)
- `THEAUTH_AGENT_CREDENTIAL`, `THEAUTH_PERMISSION_CREDENTIAL`, `THEAUTH_DELEGATION_CREDENTIAL` (core VC)
- `TheAuthApiError` / `TheAuthClientOptions` / `TheAuthClient` / `createTheAuthClient` (client)
- `TheAuthUser`, `TheAuthSession`, `TheAuthAgent`, `TheAuthPermission`, `TheAuthContextValue`, `TheAuthContext`, `TheAuthProvider`, `useTheAuthContext` (react)
- `THEAUTH_KEY`, `TheAuthPluginOptions`, `createTheAuthPlugin` (vue)
- `TheAuthStorage`, `TheAuthExpoConfig`, `TheAuthExpoProvider`, `useTheAuthContext` (expo)
- `TheAuthClient`, `createTheAuthClient` (svelte)
- `TheAuthSettings`, `TheAuthApiClient`, `TheAuthDashboard` (dashboard)
- `TheAuthEmailError` (email auth)
- `TheAuthNextjsOptions`, `TheAuthNextjsHandlers`, `theAuthNextjs` (nextjs adapter)
- `TheAuthNestjsOptions`, `buildTheAuthRouter`, `theAuthMiddleware`, `TheAuthModuleOptions`, `TheAuthModule` (nestjs adapter)
- `TheAuthTanStackOptions`, `TheAuthTanStackHandlers`, `theAuthTanStack` (tanstack adapter)
- `TheAuthSvelteKitOptions`, `TheAuthSvelteKitHandlers`, `theAuthSvelteKit` (sveltekit adapter)
- `TheAuthAstroOptions`, `TheAuthAstroHandlers`, `theAuthAstro` (astro adapter)
- `TheAuthNuxtOptions`, `theAuthNuxt` (nuxt adapter)
- `TheAuthFastifyOptions`, `theAuthFastify` (fastify adapter)
- `TheAuthSolidStartOptions`, `TheAuthSolidStartHandlers`, `theAuthSolidStart` (solidstart adapter)
- `TheAuthPrismaAdapter` (prisma adapter)

See `RENAME-MAP.md` for the full one-to-one mapping table and a migration guide.

Removal timeline: deprecated `Auth*` and `Kavach*` names will be removed in a future major version.

### @glinr/theauth-nextjs-auth v0.1.0, May 2, 2026

New package. A focused Next.js (14/15/16) adapter for apps whose auth backend lives outside Next.js (Spring, Rails, Hono, Go, etc.). Distinct from `@glinr/theauth-nextjs` which bundles the agent-management runtime — this is the "I have a backend already, just give me session + cookies + refresh on the FE" path.

Ships eight server-side helpers (`createAuthConfig`, `getServerSession`, `refreshSession`, `fetchWithRefresh`, `graphqlWithRefresh`, `buildAuthHeaders`, `buildClientHeaders`, `createSignOutAction`) and an Edge-runtime-safe `withAuth()` middleware via a `/middleware` sub-export. Cookie prefix policy: `__Host-{prefix}-token` in production, plain names in development (browsers reject `__Host-` without Secure on HTTP localhost). 26 tests passing.

### v0.4.2, April 18, 2026

Fix on a missed barrel in 0.4.0. The ten new OAuth providers were added to `providers/index.ts` but the top-level `auth/index.ts` still pointed at the old nine-provider list, so `import { notion } from "@glinr/theauth/auth"` did not resolve. `auth/index.ts` now re-exports the whole barrel, so providers added in later releases pick themselves up automatically.

### v0.4.1, April 18, 2026

`@glinr/theauth/standards` shipped in 0.4.0 but was missing from the `exports` field in `package.json` and from the tsup build entries, which meant `import { AGENTIC_JWT_CLAIMS } from "@glinr/theauth/standards"` failed at resolve time. Both are fixed.

### v0.4.0, April 18, 2026 (v3 wave)

Four things shipped together.

- **Agentic JWT claim constants.** The two relevant IETF drafts (`draft-goswami-agentic-jwt-00` and `draft-liu-agent-operation-authorization-01`) are encoded as typed constants. Enabling the new `emitAgenticJwtClaims` config flag populates `agent_id`, `agent_type`, and `trust_tier` on every issued token. Off by default so existing deployments do not change shape on upgrade.
- **Ten OAuth providers promoted to first-class.** Notion, Spotify, Discord, Slack, Twitch, Reddit, Figma, Dropbox, Zoom, and Atlassian each ship as a named export with a typed factory, a `DEFAULT_X_SCOPES` constant, and a profile normaliser. Three files of boilerplate you no longer write per provider.
- **Audit export as Verifiable Credentials.** `exportAuditAsVC` in the new `@glinr/theauth/vc` subpath writes your audit log out as a W3C VC (`ldp_vc` or `jwt_vc`, individual events or a Verifiable Presentation). Useful for compliance exports that downstream auditors can verify without touching your database.
- **`@glinr/create-theauth-app` on npm.** `pnpm create theauth-app my-app` now scaffolds a working Next.js App Router template.

### v0.3.0, April 17, 2026

Two adapter additions and a schema defaults change.

- **`cookieAuth()` adapter.** Validates a JWT from an httpOnly cookie set by a non-Node backend (Go, Python, Rust). Use this when the canonical session already exists upstream and theauth is the read side.
- **`KavachProvider` external mode.** The React provider can now delegate auth to any external API. Same session semantics, different source of truth.
- **Feature-gated table creation.** The migrator only creates tables for features you turn on. Projects that do not use passkeys no longer get passkey tables.

### v0.2.1, April 3, 2026

Three small but load-bearing fixes.

- PKCE `code_verifier` is now sent during the token exchange for GitHub, LinkedIn, and Slack. Without it those providers would reject the exchange for any app that had code challenge on.
- Cookies no longer set the `Secure` flag when the origin is not HTTPS. Local dev on `http://localhost` works again.
- `requireAuth` tests updated for the new enforcement path.

### v0.2.0, April 3, 2026

Auth hardening wave. Stricter `requireAuth` enforcement, production-ready cookie defaults, and the PKCE exchange fixes that got polished in 0.2.1.

### v0.1.x, April 3, 2026

Five patches consolidating the launch release. Stable exports, clean build artifacts, working CLI version detection, launch docs.

### v0.1.0, April 3, 2026 (launch)

First release with a real semver contract. Core and the primary client-facing packages were promoted to the 0.1 line. Adapters, plugins, and the dashboard stayed on their existing tracks for a separate coordinated versioning pass.

---

## Per-package changelogs

Each package has its own `CHANGELOG.md` generated from the changeset history. For release-by-release notes down to the patch level see:

- [`packages/core/CHANGELOG.md`](packages/core/CHANGELOG.md) for `@glinr/theauth`
- [`packages/cli/CHANGELOG.md`](packages/cli/CHANGELOG.md) for `@glinr/theauth-cli`
- [`packages/test-utils/CHANGELOG.md`](packages/test-utils/CHANGELOG.md) for `@glinr/theauth-test-utils`
- Adapters and framework packages: each `packages/*/CHANGELOG.md`

## Versioning

- `@glinr/theauth` (the core) follows semver. Breaking changes are reserved for major bumps.
- Adapters under `@glinr/theauth-*` are versioned independently. Each adapter's README pins the core version range it supports.
