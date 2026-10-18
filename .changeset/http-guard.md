---
"@glinr/theauth": minor
"@glinr/theauth-conformance": minor
---

Add the remote guard protocol. `httpGuard({ name, url, secret })` turns an HTTPS endpoint run by a guard vendor (for example HOL Guard) into a `beforeAuthorize` hook. Requests are signed with HMAC-SHA256 over `<timestamp>.<body>` (`x-theauth-timestamp`, `x-theauth-signature: v1=<hex>`), responses must be signed too (`x-theauth-response-timestamp`, `x-theauth-response-signature: v1=<hex HMAC-SHA256 of "<requestId>.<responseTimestamp>.<body>">`, bound to the request id, same replay window, required by default, `requireSignedResponse: false` opts out for local development only, optional `responseSecret`), responses are validated with a strict schema, redirects are never followed, plain http is refused outside localhost, and every failure denies through the existing hook runner. `verifyGuardRequest(secret, headers, body)` and `signGuardResponse(secret, { requestId, body })` are exported for vendors.

`@glinr/theauth-conformance` gains guard mode: `npx @glinr/theauth-conformance guard <url> --secret <s>` runs 12 checks (unsigned, wrong signature and stale requests refused, unsigned, wrongly signed, wrong request id and stale responses failed, canary allow and deny verdicts, malformed input never allowed, dryRun, no redirect, latency budget), plus a reference guard server, `startGuardReference`.

Upgrade notes: additive, nothing changes unless you call `httpGuard`. Vendors must sign their responses. The request body carries the agent, action, resource, arguments and delegation chain, so use the `redact` option to drop user data before it leaves the process. See docs/guards.mdx.
