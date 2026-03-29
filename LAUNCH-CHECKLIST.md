# KavachOS OSS Launch Checklist

## Critical (blocks launch)

| #   | Item                                                               | Effort  | Owner | Status      |
| --- | ------------------------------------------------------------------ | ------- | ----- | ----------- |
| 1   | Write core tests (permission, agent, session, auth flow, adapters) | 2-3 hrs | Codex | In progress |
| 2   | Fix tsup entries (crypto, redirect missing from build)             | 5 min   | Codex | Done        |
| 3   | Fix CLI version hardcode (reads 0.0.1 instead of package.json)     | 2 min   | Codex | Done        |

## Important (should do before launch)

| #   | Item                                                  | Effort | Owner  | Status                                           |
| --- | ----------------------------------------------------- | ------ | ------ | ------------------------------------------------ |
| 4   | Create CHANGELOG.md                                   | 15 min | Claude | Done                                             |
| 5   | Create SECURITY.md                                    | 10 min | Claude | Done                                             |
| 6   | Bump to 0.1.0 (changeset)                             | 5 min  | Claude | Done (Wave A/B strategy + explicit major wave)   |
| 7   | Lower Node requirement to >= 20 (from >= 22)          | 2 min  | Claude | Done                                             |
| 8   | Clean orphan dirs (packages/auth/, packages/plugins/) | 5 min  | Claude | Done (dirs are active, no orphan cleanup needed) |
| 9   | Per-adapter READMEs (npm shows blank)                 | 30 min | Claude | Done                                             |
| 10  | Verify .env is gitignored                             | 1 min  | Claude | Done                                             |

## Release notes

- Current root Node engine is already set to >=20.0.0.
- Adapter README files exist for all 11 adapters.
- .env and .env.\* are gitignored with .env.example allowlisted.
- Added Wave A changeset: .changeset/launch-0-1-0.md.
- Added Wave B changeset: .changeset/launch-adapters-and-plugins-1-0-0.md.
- Release runbook added: docs-local/release-versioning-runbook-2026-03-29.md.
- Strategy selected: accept adapter/plugin majors, split releases into waves, and apply the runbook policy guardrail.

## Nice to have (post-launch)

| #   | Item                                   | Notes                 |
| --- | -------------------------------------- | --------------------- |
| 11  | Add Discord badge/link to npm pages    | Community building    |
| 12  | GitHub repo topics and description     | SEO / discoverability |
| 13  | Add OpenGraph image for social sharing | Marketing             |
| 14  | Write blog post for launch             | HN/Reddit/Twitter     |
| 15  | Submit to awesome-\* lists             | Community reach       |
