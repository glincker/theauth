# Governance

This document describes how KavachOS OSS is maintained and how decisions are made.

## Project goals

- Build reliable, secure auth primitives for AI agents and humans.
- Keep APIs understandable and stable.
- Maintain transparent release and security processes.

## Roles

### Maintainers

Maintainers can:

- Review and merge pull requests
- Manage releases and package publishing
- Triage issues and discussions
- Enforce security and conduct policies

Maintainers are expected to be active, responsive, and transparent in technical decisions.

### Contributors

Contributors can:

- Submit issues, discussions, and pull requests
- Propose API and architecture changes
- Help with docs, tests, and examples

## Decision process

### Small changes

Routine fixes, docs updates, and non-breaking improvements are approved by maintainer review in PR.

### Significant changes

For larger or breaking changes:

1. Open a GitHub Discussion or issue proposal.
2. Define migration impact and compatibility risk.
3. Obtain maintainer agreement before implementation.
4. Include tests and release notes.

## Release policy

- Follow changesets-based versioning.
- Use explicit release waves when dependency cascades are expected.
- Document breaking changes in changelog/release notes.

## Security and conduct

- Security reports follow SECURITY.md.
- Community behavior follows CODE_OF_CONDUCT.md.

## Becoming a maintainer

Potential maintainers are invited based on sustained, high-quality contributions across code, review, and community support.

Evaluation criteria:

- Consistent technical quality
- Responsible communication
- Strong review discipline
- Demonstrated project stewardship
