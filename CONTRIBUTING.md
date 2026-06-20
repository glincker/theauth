# Contributing to TheAuth

Thanks for contributing. This guide helps you ship changes quickly and safely.

## Response times

We respond to issues and PRs within 48 hours on weekdays. If you don't hear back, ping the thread or open a discussion. Threads tend to move faster than email.

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
pnpm --filter theauth test
pnpm --filter @theauth/cli test
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

For coordinated release waves across multiple packages, open a discussion before bumping. The maintainer will help line up the changesets so the release graph stays clean.

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
- Questions: GitHub Discussions
- Security issues: follow [SECURITY.md](SECURITY.md)
- Support channels: [SUPPORT.md](SUPPORT.md)
