# theAuth

Open-source TypeScript auth that gives AI agents their own identity, scoped permissions, delegation and an audit trail, next to normal human sign in.

[![npm](https://img.shields.io/npm/v/@glinr/theauth?style=flat&label=npm)](https://www.npmjs.com/package/@glinr/theauth)
[![CI](https://img.shields.io/github/actions/workflow/status/glincker/theauth/ci.yml?branch=main&style=flat&label=CI)](https://github.com/glincker/theauth/actions/workflows/ci.yml)
[![CodeQL](https://github.com/glincker/theauth/actions/workflows/codeql.yml/badge.svg)](https://github.com/glincker/theauth/actions/workflows/codeql.yml)
[![License](https://img.shields.io/github/license/glincker/theauth?style=flat&label=license)](LICENSE)

[Website](https://theauth.dev) | [Docs](https://docs.theauth.dev) | [Quickstart](https://docs.theauth.dev/quickstart) | [Playground](https://docs.theauth.dev/playground) | [Examples](examples) | [Go library](https://github.com/glincker/theauth-go)

## Quickstart

Needs Node 20 or newer. This runs as pasted, with an in-memory SQLite database.

The snippet needs 2.0.0, the version in this repo. npm `latest` was 1.2.0 on 2026-10-31, which has no `auth.user`. I ran it against a local build and got the output in the comments, so build `packages/core` until 2.0.0 ships.

```bash
npm install @glinr/theauth
```

```typescript
import { createTheAuth } from "@glinr/theauth";

const auth = await createTheAuth({
  database: { provider: "sqlite", url: ":memory:" },
  agents: { enabled: true },
});

// An agent needs an owner row. Human sign in creates these for you.
const owner = await auth.user.create({ email: "owner@example.com", name: "Owner" });

const agent = await auth.agent.create({
  ownerId: owner.id,
  name: "github-reader",
  type: "autonomous",
  permissions: [{ resource: "mcp:github:*", actions: ["read"] }],
});

const read = await auth.authorize(agent.id, { action: "read", resource: "mcp:github:repos" });
const write = await auth.authorize(agent.id, { action: "write", resource: "mcp:github:repos" });
console.log(read.allowed, read.code); // true allowed
console.log(write.allowed, write.code); // false no_permission
```

`agent.token` starts with `ta_` and is shown once. To serve this over HTTP, mount a [framework adapter](https://docs.theauth.dev/packages#framework-adapters).

## Why

Agents are principals with owners, not shared API keys. A parent agent can hand part of its permissions to a child, and revoking any link takes effect on the next call. Every decision returns a machine-readable code and writes an audit row.

It runs on Node, Bun, Deno and Cloudflare Workers with four runtime dependencies in core (`drizzle-orm`, `jose`, `sql.js`, `zod`). No hosted service needed.

## Status

Versions follow [STABILITY.md](STABILITY.md): stable is 1.0 or later, beta is 0.2 to 0.9, experimental is 0.1.

| Area | Status | Notes |
|---|---|---|
| Core, email, MCP, gateway, CLI, client | Stable | SemVer, breaking changes only in majors. Repo is at core 2.0.0, npm is at 1.2.0 |
| React, Vue, Svelte, Expo, Electron, UI, dashboard, test utils | Beta | May change between minor releases |
| Browser extension package | Experimental | 0.1.0 |
| SAML | Experimental | Our own verifier, no independent audit |
| Cookie session cache | Experimental, opt in | Can lag a revocation by up to its `maxAge` |
| Databases | SQLite tested in CI | Postgres run by hand, D1 untested, MySQL unsupported |

All 30-odd packages, versions and every known limit: [Packages and status](https://docs.theauth.dev/packages). Not sure it fits? Read [When not to use theAuth](https://docs.theauth.dev/when-not-to-use).

## Packages

The full table with versions and maturity lives in [Packages and status](https://docs.theauth.dev/packages). Core is in [`packages/core`](packages/core).

## Related

- [theauth-go](https://github.com/glincker/theauth-go): the Go server library (v2), with the same model. It is separate from the Go REST client in [`sdks/go`](sdks/go).
- [Python client](https://pypi.org/project/theauth/) and [Terraform provider](https://registry.terraform.io/providers/glincker/theauth).
- Formerly kavachOS: see the [rename map](RENAME-MAP.md).

## How this was built

Parts of this codebase were written with AI assistance. The code is covered by about 5,000 test cases (a textual count, see [by the numbers](https://docs.theauth.dev/packages#by-the-numbers)) plus CodeQL in CI. It has had no third party security audit. If you find a problem, open an issue or report it privately as described in [SECURITY.md](SECURITY.md).

## Contributing and license

Questions: [Discussions](https://github.com/glincker/theauth/discussions) or the [GLINR Discord](https://discord.gg/Ar5pcaZB99). See [CONTRIBUTING.md](CONTRIBUTING.md) and [CHANGELOG.md](CHANGELOG.md).

[MIT](LICENSE). Built by [GLINCKER](https://glincker.com), a [GLINR STUDIOS](https://glinr.com) company.
