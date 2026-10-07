# Maintainers Guide

TheAuth is maintained by GLINR STUDIOS, a GLINCKER LLC project. This document defines maintainer responsibilities and the release workflow.

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

- All inquiries (security, conduct, general): support@glincker.com
