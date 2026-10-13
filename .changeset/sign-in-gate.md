---
"@glinr/theauth": minor
---

Central sign-in gate. Every session-issuing path (username, magic link, passkey, and the OAuth callback via `ctx.signInGate`) now asks one gate whether a session may be issued. A forced password change returns a signed challenge instead of a hard block, and users with TOTP enabled get a `two_factor_required` challenge for the methods in `signInGate.require2faFor` (default when `signInGate` is set: password, social, magic_link). New routes `POST /auth/sign-in/two-factor` and `POST /auth/sign-in/password-change` finish the flow. Optional trusted devices (`signInGate.trustedDevice.enabled`, default off) skip 2FA through a random device cookie, are listed and revoked at `/auth/trusted-devices`, and are revoked on any password change. `SignInGateError` is thrown by `username.signIn` and `magicLink.verify`, with the existing "Password reset required" message kept.

Session limits. `auth.session.maxConcurrent` with `onLimit: "evict-oldest" | "reject"` caps concurrent sessions per user inside `sessionManager.create`. `auth.session.onRevoke` reports revoked sessions.

OIDC logout. `createOidcProviderModule({ logout })` adds an RP-initiated `end_session_endpoint` (id_token_hint and post_logout_redirect_uri allowlist validation), advertises `end_session_endpoint` and `backchannel_logout_*` in discovery, adds `sid` to ID tokens, and fans out back-channel logout tokens to each client's `backchannel_logout_uri` on logout and on session revoke. Failures never block local logout. `createBackChannelLogoutReceiver` can now revoke local sessions by sid or sub through a session manager or an injected `revokeSessions` callback. Adds two tables, `theauth_oidc_logout_clients` and `theauth_oidc_sessions`.
