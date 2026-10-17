---
"@glinr/theauth": patch
---

`theauth.delegation.revoke(chainId, opts?)` now accepts `{ revokedBy }` and forwards it, so the `delegation.revoke` audit rows record who revoked the chain instead of null.
