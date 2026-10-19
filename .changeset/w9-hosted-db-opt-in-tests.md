---
"@glinr/theauth": patch
---

Opt-in real-endpoint tests for Turso, Neon and Supabase (`packages/core/tests/store-contract/hosted.test.ts`). Each suite is skipped unless its variable is set (`THEAUTH_TEST_TURSO_URL` and `THEAUTH_TEST_TURSO_AUTH_TOKEN`, `THEAUTH_TEST_NEON_URL`, `THEAUTH_TEST_SUPABASE_URL`), and `THEAUTH_TEST_HOSTED_RESET=1` drops the `theauth_*` tables around a run. Documented on the hosted databases page.
