---
"@glinr/theauth": minor
"@glinr/theauth-cli": minor
---

API keys: when `apiKeys` has no `grantablePermissions` and the `org` module is on, a self service key is now capped by the creator's org roles through `org.hasPermission`. Before, every non-empty permission list was refused. Still fails closed with no org membership, no org module or a failing lookup.

`theauth doctor --security` adds seven findings: `sec.api_keys.no_scope_resolver`, `sec.device.path_matching_off`, `sec.device.mid_wildcard`, `sec.device.bundle_ttl_long`, `sec.device.no_attestation`, `sec.approval.no_step_up` and `sec.agent.dpop_not_required`.
