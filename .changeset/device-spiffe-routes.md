---
"@glinr/theauth": minor
"@glinr/theauth-dashboard": minor
---

SPIFFE bridge over HTTP, with audit rows. Set `devices.spiffe` (trust domains, audience, `agentMap` or `resolveAgent`, optional `clientCertificate` or `trustedProxyHeader`, `rateLimit`) and the handler serves `POST /device/spiffe/verify`, `POST /devices/spiffe/verify`, `POST /devices/spiffe/token` and `POST /devices/:id/spiffe`. They are in `sdks/openapi.json`.

- Minting and linking are admin only. An X.509 chain is never read from the body of the device route, only from your `clientCertificate` callback or the one header you name in `trustedProxyHeader` (off by default, your proxy must overwrite it). Every route is rate limited per client and fails closed; the `rateLimit()` plugin has a new key `deviceSpiffe`.
- Every verification outcome is reported to `onOutcome` and written to the audit log as `device.spiffe.authenticate` or `device.spiffe.verify` when it maps to a device or agent. Rows hold the SPIFFE ID, failure code and certificate thumbprint, never the certificate or token. `createSpiffeBridge` gained `onOutcome` and `verify()`.
- Dashboard: the Devices page lists SPIFFE identities with their trust domain and can link an id.
