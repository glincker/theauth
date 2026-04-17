# Maintainer Triage Playbook

Operational guide for handling issues, PRs, and support in the KavachOS repository.

## Daily triage loop

1. Review new issues and discussions.
2. Validate reproduction details and assign labels.
3. Route security-sensitive reports to private channels.
4. Mark stale/incomplete reports with requested info.
5. Prioritize by impact and user risk.

## Issue classification

Use clear labels and one primary milestone/priority.

Suggested priority model:

- P0: Security bypass, auth/permission break, data loss
- P1: High-impact regressions, release blockers
- P2: Normal defects and quality improvements
- P3: Enhancements and roadmap items

## Required info for bug triage

- Package and version
- Runtime environment (Node/OS/database)
- Minimal reproduction
- Expected vs actual behavior
- Logs/trace with secrets redacted

If missing, request info before assigning implementation work.

## PR triage checklist

- Scope is focused and understandable
- Tests cover behavior changes
- Lint/typecheck/build pass
- Changeset added when user-visible behavior changed
- Breaking changes documented

## Security routing

If report suggests vulnerability:

- Do not discuss exploit details publicly
- Ask reporter to use security@kavachos.com
- Track privately until fix is released

## SLA guidance

- New issue acknowledgment: 2 business days
- PR first response: 2 business days
- Security intake acknowledgment: 48 hours

## Closure policy

Close issues when:

- Fixed and released
- Cannot reproduce after requested details window
- Out of scope with clear explanation
- Duplicate of existing tracked issue

Always leave a short, respectful closing note with next steps where possible.
