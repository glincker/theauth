---
"@glinr/theauth": minor
"@glinr/theauth-cli": minor
"@glinr/theauth-dashboard": patch
---

SPIFFE workload identity bridge. `createSpiffeBridge` verifies an X.509-SVID (one `spiffe://` URI SAN, leaf rules of the X509-SVID spec, path validation against a configured trust bundle) or a JWT-SVID (audience checked, short expiry) and maps the SPIFFE ID to an existing device or agent. An X.509-SVID also yields the RFC 8705 `x5t#S256` confirmation, and an agent can get a token bound to the certificate with `bridge.issueAgentToken`. Trust bundles can come from static roots, a bundle document, or a SPIFFE bundle endpoint refreshed on demand (https only, size and time limits, rollback guard on `spiffe_sequence`, fail closed when stale).

Devices get a new credential kind `spiffe` (`device.addCredential(id, { kind: "spiffe", spiffeId })`, owner side only, enrollment refuses it) and `device.findBySpiffeId`. The CLI gains `theauth device spiffe verify-x509`, `verify-jwt` and `link`. The dashboard credential type lists the new kind.
