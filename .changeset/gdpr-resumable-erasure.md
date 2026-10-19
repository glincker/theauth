---
"@glinr/theauth": patch
---

`gdpr.deleteUser` is now resumable and idempotent. It runs as ordered steps with a progress marker, so a crash or database error halfway is finished by calling it again, and two concurrent calls leave one clean result. Audit erasure writes each `audit.erasure` record once (deterministic id) and rewrites rows per agent in a rerun-safe order. `gdpr.anonymizeUser` applies its credential deletes and user update as one atomic batch. `organization.remove` is one atomic batch. Fixes along the way: revoking a delegation link writes its audit row before flipping the status and `revokeAllForAgent` resumes cascades through already revoked links, and `exportUserData` no longer drops audit rows for users who own no agents.
