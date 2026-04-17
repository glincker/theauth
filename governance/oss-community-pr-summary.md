# PR Summary: OSS Governance and Contribution Experience

## Title

docs: strengthen OSS contribution, support, and governance framework

## Summary

This PR improves contributor onboarding, maintainer operations, and community support workflows for KavachOS OSS.

## What changed

- Added SUPPORT.md with support channels, intake requirements, and response expectations.
- Added GOVERNANCE.md with project roles, decision process, and maintainer pathway.
- Added MAINTAINERS.md workflow guidance and release lane ownership.
- Added issue template configuration with discussion, Discord, and security contact routing.
- Added FUNDING.yml to enable sponsorship links.
- Improved CONTRIBUTING.md with monorepo workflow and changeset expectations.
- Improved PR template with release-impact and changeset checks.
- Added maintainer triage playbook and label taxonomy docs.
- Linked governance and support docs from README.

## Why this matters

- Reduces contributor friction and clarifies contribution standards.
- Speeds maintainer triage and improves issue quality.
- Clarifies security and support routes.
- Makes release governance more predictable in a multi-package monorepo.

## Risk

Low. Documentation and GitHub template/config changes only.

## Validation

- Verified files are tracked and linked from contributor-facing docs.
- No runtime code path changes.

## Follow-up

- Align GitHub repository labels to docs/triage-label-taxonomy.md.
- Enable and curate GitHub Discussions categories.
- Review SLA targets quarterly.
