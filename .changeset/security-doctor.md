---
"@glinr/theauth-cli": minor
---

Add `theauth doctor --security`, a linter for the security settings of a config file (`theauth.config.mjs`, `.js` or `.json`, or `--config <file>`). It reads the real `TheAuthConfig` and checks the secrets, the redirect cookie flags, the session cookie `__Host-` prefix, PBKDF2 iterations, a missing `rateLimit()` plugin, login lockout, wildcard `allowedHosts`, an empty redirect allowlist, offline MCP revocation, and org and apiKeys handlers opened with `trustedServerUse`.

Each finding has a stable `sec.*` id, a severity (`high`, `medium`, `low`), a one line fix and a docs link. `--json` prints `{ ok, failOn, findings }`. The command exits 1 when a finding reaches `--fail-on` (default `high`) and 2 on a usage or config load error, so it can gate CI. See `docs/security-doctor.mdx`.
