---
"@glinr/theauth": minor
---

New subpath `@glinr/theauth/testing/devices`: a fleet simulator and conformance kit for devices. `createDeviceFleet({ size })` enrolls N simulated devices against a real in-memory theAuth through the real HTTP handler, with a virtual clock (`fleet.clock`) so runs are repeatable. `runDeviceConformance(fleet)` checks enrollment, assertions, bundle and revocation snapshot verification, offline and online use, clock skew, rollback and revocation in the middle of a session. Measured p50 and p99 at 1000 devices are in `docs/device-conformance-kit.mdx`.
