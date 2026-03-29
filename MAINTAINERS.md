# Maintainers Guide

This document defines maintainer responsibilities and release workflow for KavachOS OSS.

Related docs:

- Governance: `GOVERNANCE.md`
- Support policy: `SUPPORT.md`
- Triage operations: `docs/maintainer-triage-playbook.md`
- Label taxonomy & sync: `docs/triage-label-taxonomy.md` + `.github/labels.yml`
- GitHub Discussions setup: `docs/discussions-playbook.md`
- PR summary template: `docs/oss-community-pr-summary.md`
- Release strategy: `docs-local/release-versioning-runbook-2026-03-29.md`

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

KavachOS uses explicit release waves:

1. Wave A: core + primary client-facing packages (`0.1.x` line)
2. Wave B: adapters/plugins major alignment (`1.0.x` line)
3. Dashboard remains on independent cadence

See: `docs-local/release-versioning-runbook-2026-03-29.md`

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

- Security: security@kavachos.com
- Conduct: conduct@kavachos.com
- General: hello@kavachos.com
