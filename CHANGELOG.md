# Changelog

This monorepo uses [Changesets](https://github.com/changesets/changesets). Each package has its own changelog generated from the changeset history.

For a release-by-release record, see:

- GitHub Releases: <https://github.com/kavachos/kavachos/releases>
- Per-package changelogs:
  - [`packages/core/CHANGELOG.md`](packages/core/CHANGELOG.md) — `kavachos`
  - [`packages/cli/CHANGELOG.md`](packages/cli/CHANGELOG.md) — `@kavachos/cli`
  - [`packages/test-utils/CHANGELOG.md`](packages/test-utils/CHANGELOG.md) — `@kavachos/test-utils`
  - Adapters and framework packages: see each `packages/*/CHANGELOG.md`

## Versioning

- `kavachos` (the core package) follows semver. Breaking changes are reserved for major bumps.
- Adapters under `@kavachos/*` are versioned independently. Each adapter's README pins the core version range it supports.
