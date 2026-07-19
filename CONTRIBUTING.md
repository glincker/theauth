# Contributing to theauth

Thanks for contributing. This guide gets you set up and explains the conventions we follow.

We respond to issues and PRs within 48 hours on weekdays. If you do not hear back, ping the thread or open a [Discussion](https://github.com/glincker/theauth/discussions). Threads move faster than email.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Development setup

Prerequisites: Node.js 20+, pnpm 9+.

```bash
git clone https://github.com/glincker/theauth.git
cd theauth
pnpm install
pnpm build
pnpm test
```

Turbo wires the build graph across packages. Running `pnpm build` at the root is enough. For hot-reloading during development:

```bash
pnpm dev
```

---

## Monorepo commands

| Command | What it does |
|---|---|
| `pnpm build` | Build all packages (via Turbo) |
| `pnpm test` | Run all test suites |
| `pnpm typecheck` | TypeScript strict check across all packages |
| `pnpm lint` | Biome lint |
| `pnpm lint:fix` | Biome lint with auto-fix |
| `pnpm format` | Biome format |

Run a command for one package:

```bash
pnpm --filter @glinr/theauth test
pnpm --filter @glinr/theauth-nextjs typecheck
```

---

## Development workflow

1. Fork the repo and create a branch from `main`.
2. Name branches using the convention: `feat/<topic>`, `fix/<topic>`, `docs/<topic>`, `chore/<topic>`.
3. Make a focused change (one feature, fix, or refactor per PR).
4. Add or update tests for any behavior change.
5. Run the full check suite before pushing:

   ```bash
   pnpm typecheck && pnpm lint && pnpm test
   ```

6. Open a PR against `main`. Use the PR template.

---

## Branch naming

| Prefix | When to use |
|---|---|
| `feat/` | New feature or capability |
| `fix/` | Bug fix |
| `docs/` | Documentation or examples only |
| `refactor/` | No behavior change, code quality |
| `perf/` | Performance improvement |
| `test/` | Tests only |
| `chore/` | Deps, CI, tooling |

---

## Commit message format

```
<type>: <short description>
```

Types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `chore`

Examples:

```
feat: add CIBA approval flow for agent tool calls
fix: prevent session fixation on token rotation
docs: add SvelteKit quick start example
```

No em dashes. No en dashes. See the style rule below.

---

## Style and quality rules

Biome handles formatting and linting. Pre-commit hooks run checks and block commits that fail.

Additional rules enforced in review:

- No `any` types. Define proper interfaces in shared types files.
- No `@ts-nocheck`. Fix the types instead.
- No `console.log` in production code. Use a logger or remove after debugging.
- Max 500 lines per file. Split into composable hooks or modules.
- No inline styles in UI components. Use Tailwind only.
- No new icon sets. Use Lucide only.

### Em-dash rule

**Never use em dashes (--) or en dashes (-) anywhere**: code, comments, commit messages, docs, changelogs, PR descriptions, or issue text. Use commas, periods, parentheses, or colons instead. This is a project-wide convention.

---

## Changesets and versioning

If your PR changes user-visible behavior, add a changeset:

```bash
pnpm changeset
```

Bump type guide:

- `patch`: bug fixes with no API change
- `minor`: backward-compatible features or new exports
- `major`: breaking changes (removed or renamed exports, changed types)

For changes that touch multiple packages at once, open a Discussion before bumping so the release graph stays consistent.

---

## Testing

All new features must include tests. Use Vitest. Test files live next to their source:

```
packages/core/src/agent.ts
packages/core/src/agent.test.ts
```

Run tests for one package:

```bash
pnpm --filter @glinr/theauth test
```

Run with coverage:

```bash
pnpm --filter @glinr/theauth test --coverage
```

---

## Reporting issues and getting help

- Bug reports: [bug report template](https://github.com/glincker/theauth/issues/new?template=bug_report.yml)
- Feature requests: [feature request template](https://github.com/glincker/theauth/issues/new?template=feature_request.yml)
- Questions: [GitHub Discussions](https://github.com/glincker/theauth/discussions)
- Security vulnerabilities: follow [SECURITY.md](SECURITY.md), do not open a public issue

---

## Sign-off / DCO

By submitting a pull request you certify that you have the right to contribute the code under the project's MIT license. No additional sign-off is required unless the maintainer requests one.
