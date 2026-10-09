---
"@glinr/theauth": minor
"@glinr/theauth-cli": minor
---

Add an opt-in migration toolkit under `@glinr/theauth/migrate`. Importers for Auth0, Keycloak, Clerk, Better Auth, Auth.js and generic CSV or JSON feed one `importUsers` call with a dry run, idempotent re-runs and conflict policies. Lazy password migration verifies PBKDF2, scrypt and (with a verifier you pass) bcrypt or argon2 hashes on first login, then rehashes. `externalIssuers` accepts tokens from an existing OIDC provider with issuer, audience and algorithm pinning and a rotating JWKS cache, with optional just in time provisioning. A sticky percentage and cohort rollout (`percent: 0` is the rollback switch), a login onboarding hook that falls back to the incumbent on any failure, a shadow mode that never enforces, and a counts-only progress report. `theauth migrate plan | import | verify | status` replaces the old placeholder message. Nothing changes unless you call it.
