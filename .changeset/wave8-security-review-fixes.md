---
"@glinr/theauth": patch
---

Close race and authorization gaps found in the wave 8 security review.

- OIDC provider authorization codes and refresh tokens, JWT session refresh tokens and passkey challenges are now claimed with one conditional write, so two concurrent redemptions of the same value cannot both succeed (RFC 6749 section 4.1.2, RFC 9700 section 4.14).
- Org `handleRequest`: an invitation can only be accepted by the user it was sent to, only an owner grants the owner role, changes or removes an owner or deletes the org, and listing invitations needs owner or admin. Accepting an invitation is a single conditional write.
- `auth.session.cookieName` is honored by the plugin endpoints, headless module handlers, sign out, OAuth and passkey sign in. Before, only the sign in gate read it.
- The framework integration gate allows a tool call only on a literal `allowed: true`.
- The audit provenance filter casts to `CHAR` on MySQL, which has no `CAST AS TEXT`.
- A backdated audit write no longer recreates the pseudonym secret of a shredded period.
