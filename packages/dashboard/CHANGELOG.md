# @glinr/theauth-dashboard

## 0.4.0

### Minor Changes

- 3e3855c: Added quorum (two person) approvals. `approval.request({ requiredApprovals: 2 })`, `approval.requiredApprovals` and `approval.quorum(request)` make a request need N distinct approvers (1 to 10, default 1). Approvers must differ from the requester and from each other, one denial ends the request, each approval writes its own audit row, and the argument bound hash, single spend and expiry apply to the whole quorum. `ApprovalQuorumError` carries the code `SELF_APPROVAL`, `DUPLICATE_APPROVER` or `APPROVER_REQUIRED`.

  The admin API `POST /approvals` takes `requiredApprovals`, and approve answers `status: "pending"` until the quorum is complete. The `approval.pending` webhook payload adds `requiredApprovals` and `approvalsReceived`, and a new `approval.vote` event reports progress. The dashboard inbox shows "1 of 2 approvals". Adds migration 0013 (`required_approvals` column and `theauth_approval_votes` table).

- b7fbe38: Point the UI, Expo, Electron and dashboard callers at routes the core handler serves. Before, these calls answered 404 against a TypeScript server.

  - `@glinr/theauth-ui`: `TwoFactorVerify` posts `{ code }` to `/auth/2fa/verify` (a backup code goes in the same `code` field) and reads the core's `{ error: "..." }` body. `OAuthButtons` navigates to `/auth/oauth/authorize/:provider`, and the server builds the callback URL itself.
  - `@glinr/theauth-expo` and `@glinr/theauth-electron`: sign-in and sign-up now call `/auth/username/sign-in` and `/auth/username/sign-up` with a `username` field, the session check is `GET /auth/session` and sign-out is `POST /auth/sign-out`. New options `signInPath`, `signUpPath` and `identifierField` point them at your own email route (for example `/auth/sign-in` with `identifierField: "email"` from `@glinr/theauth-email`). Responses read the core shape `{ user, session: { token, expiresAt } }`, and the older `{ data }` envelope still works. A 5xx on the session check no longer signs the user out.
  - `@glinr/theauth-electron`: `openOAuthWindow` opens `/auth/oauth/authorize/:provider` and waits for the core callback to redirect back before it reports success, instead of closing the window on the provider redirect that carries `code=`.
  - `@glinr/theauth-dashboard`: revoking an agent uses `DELETE /agents/:id`, and an agent's permissions come from `GET /agents/:id`. The Users, Permissions, Settings and MCP Servers pages call routes only the CLI dev server serves. Against a server without them the pages now show a "does not serve" message.

  Upgrade note: if your Expo or Electron app relied on `/sign-in/email` and `/sign-up/email`, set `signInPath`, `signUpPath` and `identifierField` to the routes your server serves.

- 3953479: New Devices page: fleet health counters from `GET /devices/stats`, a device list you can filter by status (last seen, suspend, resume, revoke), a detail view with credential kinds, and an enrollment token form that shows the plaintext token once.

  Fixes:

  - The audit client now matches the core `GET /audit` route. It sends `actions`, `since`, `until` and `provenanceKind`, reads the bare array the route returns, resolves agent names from the agent list, and keeps `inputs`. The old client expected `{ entries, total, offset }` and sent parameters the route ignores.
  - `PaginatedAuditLogs` has `hasMore` instead of `total`, because the route returns no total. The audit table and Security page were updated to match, and `escalated` rows now render.
  - Audit export returns the response body as text. CSV exports used to fail because the client parsed them as JSON.
  - Error messages from core error bodies (`{ error: { message } }`) are shown instead of the HTTP status text. Error codes are unchanged.

- 6fb281d: The dashboard gains an Explain page and a Revocations page, and the approvals inbox now says so when the approvals API is not mounted.

  Explain takes an agent id, action and resource and calls `POST /explain`, showing the decision code, the matched grant, constraint steps and the closest grants that nearly matched. Revocations shows the live `theauth_mcp_revocations` rows, the revocation bus counters, every live delegation link with the links and tokens a revoke would deny, and a revoke action for delegations, agents, users, clients and tokens. Every revoke is written to the audit log.

  Core `adminApi` adds `GET /revocations`, `GET /revocations/delegations` and `POST /revocations`. Security fix: `DELETE /delegations/:id` on the admin API now pushes the revoked links to the instance revocation bus. Before, only the chain rows changed, so MCP tokens tied to a revoked delegation stayed valid on other instances until they expired.

  Upgrade notes: mount the admin API at `/api` for the dashboard to reach the new routes. A core without them answers 404 and the page shows a short notice instead of failing.

- d62a425: SPIFFE bridge over HTTP, with audit rows. Set `devices.spiffe` (trust domains, audience, `agentMap` or `resolveAgent`, optional `clientCertificate` or `trustedProxyHeader`, `rateLimit`) and the handler serves `POST /device/spiffe/verify`, `POST /devices/spiffe/verify`, `POST /devices/spiffe/token` and `POST /devices/:id/spiffe`. They are in `sdks/openapi.json`.

  - Minting and linking are admin only. An X.509 chain is never read from the body of the device route, only from your `clientCertificate` callback or the one header you name in `trustedProxyHeader` (off by default, your proxy must overwrite it). Every route is rate limited per client and fails closed; the `rateLimit()` plugin has a new key `deviceSpiffe`.
  - Every verification outcome is reported to `onOutcome` and written to the audit log as `device.spiffe.authenticate` or `device.spiffe.verify` when it maps to a device or agent. Rows hold the SPIFFE ID, failure code and certificate thumbprint, never the certificate or token. `createSpiffeBridge` gained `onOutcome` and `verify()`.
  - Dashboard: the Devices page lists SPIFFE identities with their trust domain and can link an id.

- fe7e6c6: Input provenance end to end.

  - Content hashes in `input_provenance` are now HMAC-SHA-256 under an HKDF subkey of the audit key (version tag `hv: 2`). Old plain hashes still match. `hashInputContent(content, auditKey)` takes the key now, `hashInputContentPlain` is the old function (breaking for callers that hashed themselves, see `docs/upgrading-to-2.mdx`).
  - `audit.query({ provenance: { content } })` hashes on the server and matches keyed and plain rows. `AuditEntry.inputs` exposes the recorded sources.
  - `POST /authorize` and `POST /authorize/token` accept `inputs` or a `TheAuth-Inputs` header. `GET /audit` takes `provenanceKind`, `provenanceHash` and `provenanceContent`. `sdks/openapi.json` is regenerated.
  - Gateway reads `TheAuth-Inputs`, records it on permission checks and audit entries, and strips it before the upstream. The admin MCP server reads `_meta["io.theauth/inputs"]` and `query_audit` takes provenance filters.
  - `theauth audit query` with `--provenance <kind>[:<hash>]` and `--input-content`, and an Inputs column with chips on the dashboard audit page.
  - `policy.taint.inputLabels` (off by default) turns the kinds of `context.inputs` into `input:<kind>` call labels, so a taint rule can hold a tool such as `tool:exec` for approval after a retrieved document was in context.

- a561306: Add observability. `observability.onDecision(event)` receives one typed event per `authorize`, `authorizeByToken` and `policy.evaluate` decision (agent, owner, action, resource, decision, code, duration, cache hit, delegation depth, hook outcome, guard). It runs in a queued microtask, so it never delays or changes a decision, and a throwing listener is swallowed and counted (`theauth.observability.stats()`). Events carry no tokens and no raw arguments, and `observability.redactResource` rewrites the resource string. A new `logger` option (`debug`, `info`, `warn`, `error`, no-op by default) receives hook timeout and listener failure warnings.

  `@glinr/theauth-plugin-telemetry` adds `theauthOtel({ tracer, meter })`: the `theauth.decisions` counter, the `theauth.decision.duration` histogram, one span per decision, and span events for hook timeouts. No new dependency.

  The dashboard audit page gains a Code column, a code filter, and a Why drawer that calls `POST /explain`.

  Upgrade notes: additive, nothing changes unless you set `observability` or `logger`. The dashboard sends `codes` to your audit endpoint and calls `/api/explain`, so mount the HTTP handler at `/api`. See docs/observability.mdx.

- a8284dc: Added `GET /devices/enrollment-tokens` and `devices.listEnrollmentTokens()`, which list tokens with usage and state and never the plaintext. The dashboard Devices page now lists enrollment tokens with a revoke button, and a device can have its groups edited, a credential added or revoked, and a policy bundle issued. The dashboard client no longer reports a network error for a 204 response.

  `DELETE /delegations/:id` now answers 204 on the admin API plugin too (it used to answer 200 with `{ revoked }`), sharing one handler with the core route. See the upgrade guide.

- 6bdec47: Device attestation goes further. A permission can now demand a hardware attested device: `constraints.attestation` takes `minSecurityLevel` (`hardware` or `strongbox`), `bootState` and `appIds`, and is decided against facts the server derives from the verified claims stored at enrollment (`attestationFacts`). It applies in `device.authorize`, in signed offline bundles (the new `att` claim) and in delegation (a child can only narrow it), fails closed for agents, users and devices without evidence, and denies with the new code `attestation_required`. The HTTP permission schemas accept it and reject unknown fields.

  Apple App Attest: `verifyAppleAssertion` checks an assertion (signature over `authenticatorData` and the client data hash, `rpIdHash`, counter), `device.verifyAppAssertion` runs it for an enrolled device and advances `theauth_devices.app_attest_counter` with one conditional update (migration 0015), so the same assertion works once. `verifyAppleReceipt` checks Apple's fraud receipt (CMS signature, chain to Apple Root CA G3, app, key, expiry) and returns the risk metric. The verifier now returns the `attestedPublicKey` claim. Tested on real recordings from veehaitch/devicecheck-appattest and block/buzz.

  TPM 2.0: `tpm2MakeCredential` and `device.tpmActivationChallenge` (route `POST /device/tpm-activation`) run the credential activation handshake, and `createTpm2CertifyVerifier` checks TPM2_Certify of the enrolled key plus the activation. Credential blobs were accepted by TPM2_ActivateCredential on a software TPM (swtpm) for RSA and ECC endorsement keys.

  The dashboard shows verified attestation claims in the device detail panel. `theauth device attest` gains `apple-assertion` and `apple-receipt` and prints the policy facts of accepted evidence.

### Patch Changes

- 372a4ec: SPIFFE workload identity bridge. `createSpiffeBridge` verifies an X.509-SVID (one `spiffe://` URI SAN, leaf rules of the X509-SVID spec, path validation against a configured trust bundle) or a JWT-SVID (audience checked, short expiry) and maps the SPIFFE ID to an existing device or agent. An X.509-SVID also yields the RFC 8705 `x5t#S256` confirmation, and an agent can get a token bound to the certificate with `bridge.issueAgentToken`. Trust bundles can come from static roots, a bundle document, or a SPIFFE bundle endpoint refreshed on demand (https only, size and time limits, rollback guard on `spiffe_sequence`, fail closed when stale).

  Devices get a new credential kind `spiffe` (`device.addCredential(id, { kind: "spiffe", spiffeId })`, owner side only, enrollment refuses it) and `device.findBySpiffeId`. The CLI gains `theauth device spiffe verify-x509`, `verify-jwt` and `link`. The dashboard credential type lists the new kind.

## 0.3.0

### Minor Changes

- 4f33ad2: The dashboard no longer keeps its secret in `sessionStorage`. `POST /api/dashboard/auth` with the secret sets an HttpOnly, SameSite=Strict session cookie that lasts eight hours, `GET` reports whether it is valid and `DELETE` signs out.

### Patch Changes

- 3a041af: Accessibility pass on the default components. Errors are announced (`role="alert"`), field errors are linked to their input with `aria-describedby` and `aria-invalid`, the loading button sets `aria-busy`, the verification code digits and backup code input have accessible names inside a labelled group, and the auth card is a region named by its title. The default slots now live in one shared module instead of four copies.

## 0.2.0

### Minor Changes

- 0fa5b1e: Remove the legacy KavachOS naming. The deprecated `Kavach*` and `createKavach` exports are gone: use `TheAuth*` and `createTheAuth`. Environment variables are now `THEAUTH_*`, webhook headers `X-TheAuth-*`, cookies and the default API route use `theauth`, and database tables are `theauth_*` (existing `kavach_*` tables are renamed in place by `createTables`, no data is lost). `Auth*` aliases remain deprecated.
