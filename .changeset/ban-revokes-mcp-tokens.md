---
"@glinr/theauth": minor
---

Banning a user now revokes their MCP tokens. `admin.banUser` pushes a `sub` revocation for the user and an `agent` revocation for each agent they own through the shared revocation bus, so unbound access tokens, refresh tokens and agent bound tokens stop working on every instance. The same push now happens for `admin.deleteUser`, GDPR erasure (`gdpr.deleteUser`) and SCIM deactivation or deprovisioning. The `sub` row is a watermark: `admin.unbanUser` does not bring tokens issued before the ban back, and the owner's agents stay revoked. `createAdminModule`, `createGdprModule` and `createScimModule` take an optional revocation bus, and plugins receive it as `ctx.revocations`.
