---
"@glinr/theauth": minor
"@glinr/theauth-cli": minor
---

IoT devices as principals (`theauth.device`, opt in with `devices` in the config). A device is backed by an agent row of type `device`, so permissions, constraints, delegation, the revocation bus and the audit chain apply unchanged.

- Credentials: pre shared keys (`tdk_`, stored as SHA-256), public keys that sign `device-assertion+jwt` assertions (RFC 7523 layout, DPoP style `jti` replay cache), and TLS client certificate thumbprints (`x5t#S256`, RFC 8705) supplied by the host.
- Enrollment with single use claim codes or bulk tokens with a use limit, claimed atomically, plus an attestation hook with single use nonces (RFC 9334 freshness).
- `device.authorize` with device states (`device_suspended`, `device_revoked`, `device_expired`, `device_not_found`) and `theauthPrincipal` on every audit row.
- Signed offline policy bundles (`device-policy+jwt`, ES256 or EdDSA, one hour default, 24 hour cap, rollback protected), with `verifyDeviceBundle` and `evaluateDeviceBundle` for the device side.
- HTTP routes under `/devices` (owner scoped) and `/device` (device facing), OpenAPI metadata, migration `0010-devices`, and `theauth device` in the CLI.

Also fixed: agent registration tokens stored any `agent_type` string the caller sent; only `autonomous`, `delegated` and `service` are accepted now. The OpenAPI generator supports discriminated unions.
