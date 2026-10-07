---
"@glinr/theauth": patch
---

Fix `ipAllowlist` denying every REST call. The permission engine now resolves the client IP from the request context first (what the framework adapters pass), then `request.ip`, so the allowlist and audit log agree.
