# migrate-from-auth0 (runnable example)

Companion to [docs/migrate/from-auth0.mdx](../../docs/migrate/from-auth0.mdx).

The guide shows the BEFORE (Auth0) and AFTER (TheAuth) shapes side by side. This folder runs the AFTER code against the real `@glinr/theauth` workspace package so the guide does not drift.

## Run

```bash
pnpm --filter @glinr/theauth-example-migrate-from-auth0 start
```

## Test

```bash
pnpm --filter @glinr/theauth-example-migrate-from-auth0 test
```

The test spawns `pnpm start`, captures stdout, and asserts every milestone that the guide claims: an M2M-equivalent agent gets created, a production permission gets gated behind approval, the staging equivalent runs through, token rotation atomically invalidates the old token, and the audit trail records every call.

## What this is not

A full Next.js app. The guide covers the handler mount for that. This file is a plain Node script that exercises the core APIs so they can be smoke-tested in CI.
