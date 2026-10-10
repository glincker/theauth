---
"@glinr/theauth": patch
---

Upgrade notes for this release. With the default session guard, a signed in user is limited to their own agents, delegations and audit rows, so an app that used the default guard as a shared admin view must pass an `authenticate` resolver that checks admin rights. The adapters and the gateway no longer read `X-Forwarded-For` or `X-Real-IP` themselves: pass `trustedProxy: { trustedProxyCount }` or `trustedProxy: { trustedHeader }` to match your proxy, otherwise an `ipAllowlist` constraint denies because the client IP is unknown. The captcha helper no longer trusts `CF-Connecting-IP` unconditionally, use `trustedProxy: { trustedHeader: "cf-connecting-ip" }` to keep it. Adapters require `@glinr/theauth` 0.7.1 or newer.
