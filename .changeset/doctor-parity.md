---
"@glinr/theauth-cli": minor
---

`theauth doctor` gains config rules that read `theauth.config.mjs` or `.js` without a database: a weak or placeholder signing secret, plain http baseUrl, WebAuthn rpId mismatch, long session lifetime, forwarded headers trusted without a proxy, missing second factor, short passwords, low PBKDF2 iterations, in-memory SAML state, offline MCP revocation without a jti denylist, unrestricted client metadata documents, missing MCP consent page, open client registration, hooks without a timeout, and audit hash-chain settings. Live mode adds `cors.wildcard` (fail) and `headers.security_off_https` (info).

Each rule has a `severity` (`info`, `warn` or `fail`). Only `fail` exits 1, as before. `--json` adds a `severity` field to these checks and keeps the existing fields. The schema is in `docs/cli-tools.mdx`.
