# Contributing to KavachOS

Thanks for contributing. This guide helps you ship changes quickly and safely.

## Code of conduct

By participating, you agree to [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Development setup

```bash
pnpm install
pnpm build
pnpm test
```

## Development workflow

1. Fork and create a branch from `main`.
2. Make a focused change (feature, fix, docs, or test).
3. Add or update tests for behavior changes.
4. Run lint, typecheck, and relevant package tests.
5. Open a PR with context and verification steps.

## Monorepo commands

```bash
pnpm build
pnpm test
pnpm typecheck
pnpm lint
```

Run commands for one package:

```bash
pnpm --filter kavachos test
pnpm --filter @kavachos/cli test
```

## Style and quality

Biome handles formatting and linting:

```bash
pnpm lint:fix
pnpm format
```

Pre-commit hooks run checks and block bad commits.

## Changesets and versioning

If your PR changes user-visible behavior, add a changeset:

```bash
pnpm changeset
```

Choose bump type carefully:

- `patch`: bugfixes with no API change
- `minor`: backward-compatible features
- `major`: breaking changes

For coordinated release waves, follow the runbook in:
`docs-local/release-versioning-runbook-2026-03-29.md`

## Pull request checklist

- `pnpm typecheck` passes
- `pnpm lint` passes
- Relevant tests pass
- New features include tests
- Breaking changes are documented
- Secrets and `.env` files are not committed

## Commit message format

Use conventional commit style:

```text
<type>: <description>
```

Types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `chore`

## Reporting issues and support

- Bug reports and feature requests: GitHub issue templates
- Questions: GitHub Discussions or Discord
- Security issues: follow [SECURITY.md](SECURITY.md)
- Support channels: [SUPPORT.md](SUPPORT.md)
