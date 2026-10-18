# @glinr/theauth-conformance

Black-box agent-auth conformance checks for any OAuth 2.1 authorization server or MCP resource server. It works over plain HTTP, needs no secrets, and ends each check as pass, fail or skip. A skip always says why. Nothing is faked.

```bash
npx @glinr/theauth-conformance https://your-server
npx @glinr/theauth-conformance https://your-server --json
npx @glinr/theauth-conformance https://your-server --badge badge.json
```

## What it covers

18 checks across:

- RFC 8414 and RFC 9728 metadata, and whether the two agree
- PKCE: S256 advertised, missing PKCE refused, `plain` refused
- Exact redirect URI matching
- Dynamic client registration (RFC 7591) and its validation
- Refresh tokens: garbage refused, rotation and reuse detection when you supply a token
- Resource indicator audience (RFC 8707) when you supply a token
- Token exchange (RFC 8693) when advertised
- Introspection (RFC 7662) when advertised
- DPoP (RFC 9449) advertised and enforced
- `WWW-Authenticate` with `resource_metadata` on a 401 from a protected MCP endpoint

Checks that need a credential are skipped unless you pass one (`--token`, `--refresh-token`, `--client-id`). The `act` claim chain check is always skipped, because it needs a subject token and client credentials.

Run `theauth-conformance --help` for every option. Exit code is 0 when no MUST check failed, 1 otherwise, 2 on a usage error.

## Guard mode

`npx @glinr/theauth-conformance guard <url> --secret <s>` checks a remote guard endpoint against the guard protocol (9 checks). See [docs/guards.mdx](../../docs/guards.mdx).

## Badge

`--badge badge.json` writes a shields.io endpoint document. Host it at a public URL and add:

```markdown
[![agent-auth conformance](https://img.shields.io/endpoint?url=https%3A%2F%2Fexample.com%2Fagent-auth-badge.json)](https://docs.theauth.dev/conformance)
```

Green means nothing failed, yellow means only SHOULD or MAY checks failed, red means a MUST failed, grey means nothing could run. The message counts only checks that ran.

## Library

```ts
import { buildBadge, runSuite } from "@glinr/theauth-conformance";

const report = await runSuite({ target: "https://auth.example.com", timeoutMs: 10000 });
console.log(report.summary, buildBadge(report));
```

Full check table and skip rules: [docs/conformance.mdx](../../docs/conformance.mdx).

MIT licensed.
