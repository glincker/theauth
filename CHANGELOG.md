# Changelog

This repo uses [Changesets](https://github.com/changesets/changesets). Per-package notes are generated automatically on release. The timeline below is the human-curated story of what each release actually delivered, pulled from those per-package changelogs and commit history.

For the full raw record see [GitHub Releases](https://github.com/kavachos/kavachos/releases) and each `packages/*/CHANGELOG.md`.

## Timeline

### v0.4.2, April 18, 2026

Fix on a missed barrel in 0.4.0. The ten new OAuth providers were added to `providers/index.ts` but the top-level `auth/index.ts` still pointed at the old nine-provider list, so `import { notion } from "kavachos/auth"` did not resolve. `auth/index.ts` now re-exports the whole barrel, so providers added in later releases pick themselves up automatically.

### v0.4.1, April 18, 2026

`kavachos/standards` shipped in 0.4.0 but was missing from the `exports` field in `package.json` and from the tsup build entries, which meant `import { AGENTIC_JWT_CLAIMS } from "kavachos/standards"` failed at resolve time. Both are fixed.

### v0.4.0, April 18, 2026 (v3 wave)

Four things shipped together.

- **Agentic JWT claim constants.** The two relevant IETF drafts (`draft-goswami-agentic-jwt-00` and `draft-liu-agent-operation-authorization-01`) are encoded as typed constants. Enabling the new `emitAgenticJwtClaims` config flag populates `agent_id`, `agent_type`, and `trust_tier` on every issued token. Off by default so existing deployments do not change shape on upgrade.
- **Ten OAuth providers promoted to first-class.** Notion, Spotify, Discord, Slack, Twitch, Reddit, Figma, Dropbox, Zoom, and Atlassian each ship as a named export with a typed factory, a `DEFAULT_X_SCOPES` constant, and a profile normaliser. Three files of boilerplate you no longer write per provider.
- **Audit export as Verifiable Credentials.** `exportAuditAsVC` in the new `kavachos/vc` subpath writes your audit log out as a W3C VC (`ldp_vc` or `jwt_vc`, individual events or a Verifiable Presentation). Useful for compliance exports that downstream auditors can verify without touching your database.
- **`create-kavachos-app` on npm.** `pnpm create kavachos-app my-app` now scaffolds a working Next.js App Router template.

### v0.3.0, April 17, 2026

Two adapter additions and a schema defaults change.

- **`cookieAuth()` adapter.** Validates a JWT from an httpOnly cookie set by a non-Node backend (Go, Python, Rust). Use this when the canonical session already exists upstream and kavachos is the read side.
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

- [`packages/core/CHANGELOG.md`](packages/core/CHANGELOG.md) for `kavachos`
- [`packages/cli/CHANGELOG.md`](packages/cli/CHANGELOG.md) for `@kavachos/cli`
- [`packages/test-utils/CHANGELOG.md`](packages/test-utils/CHANGELOG.md) for `@kavachos/test-utils`
- Adapters and framework packages: each `packages/*/CHANGELOG.md`

## Versioning

- `kavachos` (the core) follows semver. Breaking changes are reserved for major bumps.
- Adapters under `@kavachos/*` are versioned independently. Each adapter's README pins the core version range it supports.
