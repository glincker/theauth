---
"@glinr/theauth": patch
---

SPIFFE admin routes no longer reveal another owner's inactive agent. `POST /devices/spiffe/verify` now answers `unknown_workload` with the same text as an unmapped id, and `POST /devices/spiffe/token` checks ownership before it says a device is the wrong kind of workload or an agent is inactive. A failed bridge result for an inactive agent carries the `agentId` so routes can check the owner.
