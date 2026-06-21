# migrate-from-better-auth-agent-plugin (runnable example)

Companion to [docs/migrate/from-better-auth-agent-plugin.mdx](../../docs/migrate/from-better-auth-agent-plugin.mdx).

Where `@better-auth/agent-auth` models an agent as an OAuth client attached to a user, TheAuth treats `AgentIdentity` as a primary entity with delegation chains, cascading revocation, and trust scoring. This script runs the AFTER patterns from the guide against the workspace `@glinr/theauth` package so the documented shape cannot drift.

## Run

```bash
pnpm --filter @glinr/theauth-example-migrate-from-better-auth-agent-plugin start
```

## Test

```bash
pnpm --filter @glinr/theauth-example-migrate-from-better-auth-agent-plugin test
```

The test launches `pnpm start` and asserts each milestone the guide promises: the agent gets created with permissions instead of flat scopes, a child agent receives a subset through explicit delegation, `authorizeByToken` enforces the delegated permission, and revoking the parent cascades down the chain so the child loses access.

## What this is not

A framework-mounted app. See `examples/nextjs-demo` for the handler side. This folder isolates the agent + delegation surface so it can be smoke-tested in CI without a browser.
