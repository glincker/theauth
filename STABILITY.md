# Stability and versioning

This page says what you can rely on when you upgrade theAuth.

## What 1.x means

The core packages are on the 1.x line: `@glinr/theauth`, `@glinr/theauth-client`, `@glinr/theauth-mcp` and `@glinr/theauth-cli`. We follow [semantic versioning](https://semver.org/):

- Patch releases fix bugs and security issues. No behavior you rely on changes.
- Minor releases add features and may deprecate things. They stay compatible.
- Major releases are the only place a breaking change ships, and each one comes with a migration note in the changelog.

Packages still below 1.0 (most client, UI and tooling packages) may change between minor releases. The changelog of each package lists every breaking change either way.

## What is public API

For the 1.x packages, the public API is what the docs describe:

- `@glinr/theauth`: the root export and the documented subpath exports `./agent`, `./auth`, `./mcp`, `./permission`, `./migrate`, `./audit`, `./a2a`, `./vc`, `./crypto`, `./redirect`, `./standards` and `./signals`, with the options, types and HTTP routes documented at [docs.theauth.dev](https://docs.theauth.dev).
- `@glinr/theauth-client`: the exports in its README and the [client SDK guide](https://docs.theauth.dev/client-sdk).
- `@glinr/theauth-mcp`: the exports in its README and the [MCP guide](https://docs.theauth.dev/mcp).
- `@glinr/theauth-cli`: documented commands and flags, and the `--json` output shape of `theauth doctor`.
- HTTP endpoints the docs list, including request and response shapes and error codes.

Not public: anything not exported, deep imports into `dist` or `src`, internal helper modules, log message text, and the exact contents of audit metadata beyond the documented fields.

Database tables change only through shipped migrations. A migration that needs action from you is called out in the changelog.

## Which bump a change gets

Changesets decides the version from the bump you pick, so pick by effect on someone who upgrades:

| Bump | Use it for | Examples |
|---|---|---|
| patch | Bug fixes, security fixes, performance work, and internal changes with no visible effect | A wrong error code, a race in refresh, a dependency bump |
| minor | New, backward compatible capability, or a deprecation | A new option with a safe default, a new endpoint or export, `deprecated` on an old option |
| major | Anything that can break a working integration | A removed or renamed export, a changed default that alters behavior, a stricter validation that rejects what used to pass, dropping a runtime version, a migration you must run first |

If you are unsure between minor and major, ask whether an existing, correct integration could fail after upgrading. If it could, it is a major.

Version numbers count real releases. Patch numbers climb as fixes ship (1.1.1, then 1.1.2, and so on), and we do not skip or inflate them.

## Deprecations

A deprecation is announced in a minor release with a changelog entry, a note in the docs and, where practical, a runtime warning. Deprecated API keeps working until the next major release, and is not removed less than three months after the announcement.

## Supported runtimes

Node 20 or newer, Bun, Deno and Cloudflare Workers. Dropping a Node version that is still maintained is a major change. Dropping one that has reached end of life can happen in a minor release and is announced in the changelog.

## Security fixes

Security fixes go to the latest minor of the current major. The previous major gets security fixes for six months after a new major is released. Report issues privately, see [SECURITY.md](SECURITY.md).

## Framework adapters and other packages

The framework adapters, UI packages and plugins version independently, because they track their framework. Each one declares which core versions it works with in its `peerDependencies`. A core major bump does not force a major bump of an adapter that does not change.
