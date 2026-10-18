---
"@glinr/theauth": major
---

Close three 2.0 blocker gaps. The JWT session module and the stateless session manager now refuse banned users with `USER_BANNED` (stateless takes a `db` or an `isBanned` callback, and with either one a ban also ends sessions already issued). `org.handleRequest` and `apiKeys.handleRequest` fail closed: they answer 401 without an authenticate resolver, bind ids to the signed-in user, and check org membership and role. Trusted server code can opt out with `trustedServerUse: true`. The MCP authorization code grant refuses a client an admin bound to another user's agent, with `ACCESS_DENIED` at authorize and `INVALID_GRANT` at token, both carrying `details.decisionCode` `owner_mismatch`. See the upgrade notes in `docs/upgrading-to-2.mdx`.
