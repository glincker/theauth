# Maintainers Guide

TheAuth is maintained by [GLINR STUDIOS](https://glinr.com). This document defines maintainer responsibilities and the release workflow.

Related docs:

- Governance: `GOVERNANCE.md`
- Support policy: `SUPPORT.md`
- Security policy: `SECURITY.md`
- Labels: `.github/labels.yml`

## Maintainer responsibilities

- Keep CI green on `main`
- Triage issues and PRs
- Enforce contribution and security policies
- Manage releases and changelogs
- Coordinate breaking changes across packages

## Review and merge policy

- Prefer small, focused PRs
- Require passing CI and at least one maintainer review for non-trivial changes
- Require tests for all behavior changes
- Avoid merging unrelated refactors with feature/fix PRs

## Release lanes

Packages are versioned independently with Changesets. Current lines are listed in `SECURITY.md` (for example core is 0.5.x). Most packages are pre-1.0, so minor bumps may include breaking changes; call them out in the changeset.

## Release checklist

1. Run `pnpm changeset status --verbose`
2. Validate intended package bump classes (patch/minor/major)
3. Run build/typecheck/tests
4. Generate release versions with `pnpm changeset version`
5. Review changed package versions and changelog output
6. Publish using CI workflow or `pnpm release` per policy
7. Verify npm package metadata and installability

## Incident handling

- Security incidents: follow SECURITY.md process
- Regressions: revert quickly if needed, then fix forward with tests

## Contact

- All inquiries (security, conduct, general): support@glinr.com

## Release automation

Releases are mostly automatic. A maintainer only reviews and merges two kinds of PR.

1. Contributors add a changeset (`pnpm changeset`) with package source changes. The `changeset-check` workflow enforces it (label `no-changeset` skips it).
2. On every push to `main`, `version-packages` opens or updates a `chore: version packages` PR with bumped versions and changelogs.
3. Merging that PR makes the workflow push the `v<version>` tag. The tag triggers `release.yml`, which publishes to npm and creates the GitHub release.
4. When the release workflow finishes, `release-discussion` adds the release to the monthly `Releases YYYY-MM` discussion in Announcements and links it from the release notes. `theauth-go` writes to the same thread, so both repos share one post per month.

### Secrets

| Secret | Used by | Scope |
| --- | --- | --- |
| `GLINR_BOT_TOKEN` | `version-packages`, `release-discussion` | Org secret shared by GLINR repos. Fine-grained PAT (or GitHub App) with Contents, Pull requests and Discussions read and write. Must not be the default token, because tags pushed with it do not trigger `release.yml`. |
| `NPM_TOKEN` | `release.yml` | npm publish. |

Rotate tokens at least yearly. If a release did not reach the discussion, rerun `release-discussion` from the Actions tab with the tag.
