---
"@glinr/theauth": minor
"@glinr/theauth-cli": minor
---

Signed revocation snapshots for offline devices. With `devices.revocations` set, `issueBundle` (and `GET /device/bundle`) returns a signed list of the owner's revoked and suspended device ids next to the policy bundle. `verifyDeviceBundle({ revocations })` refuses a bundle with `revoked` when the device is listed and with `stale_revocations` when the snapshot is missing, expired or older than `maxAgeSeconds`. `verifyRevocationSnapshot` answers membership for peers. The Go package `iot/device` verifies the same format against shared vectors.

Built in Android Key Attestation verifier for the enrollment hook: `createAndroidKeyAttestationVerifier` and `googleRevocationList`, plus `theauth device attest android` in the CLI. Tested against the real chains in google/android-key-attestation, see the IoT docs for what that does and does not cover.

Behavior change: attestation evidence without a nonce is now refused unless `attestation.requireNonce` is false, and the hook input carries `credentialKind` and `credentialKeyThumbprint`. See the upgrade guide.
