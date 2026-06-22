---
title: TheAuth vs Hanko
description: TheAuth versus Hanko across passkey support, OAuth providers, agent identity, MCP OAuth, RBAC, and licensing. Includes a clear decision framework for each tool.
---

# TheAuth vs Hanko

Hanko is built around one idea: passkeys should be the default, not the fallback. It is a focused library with a Go backend, official TypeScript bindings, and an AGPL license. If passkeys are your entire auth surface and you have zero agent workloads, it is worth a serious look.

TheAuth includes passkey support as one method among many. The bigger difference is what happens after the human authenticates: TheAuth was designed for the agent layer that comes next.

## Feature matrix

| Capability | TheAuth | Hanko |
|---|---|---|
| License | MIT | AGPL (backend), MIT (JS SDK) |
| Primary focus | Agent-first auth SDK | Passkey-first auth |
| TypeScript SDK | Yes, first-party | Yes, first-party |
| Named OAuth providers | 37 | ~3 (Google, Apple, GitHub) |
| Passkey support | Yes | Yes, core focus |
| MCP OAuth 2.1 server | Built in | Not shipped |
| Agent identity | First-class `AgentIdentity` entity | Not shipped |
| RBAC / permissions | Unified RBAC + ABAC + ReBAC | Not shipped |
| Ephemeral sessions | Built in with auto-expiry and audit grouping | Not shipped |
| Edge runtime | Web Crypto throughout | Go backend required |
| Self-hostable | Yes | Yes |

## Pick TheAuth if

- You need more than passkeys: OAuth providers, agent identity, or a policy engine.
- You are building AI-powered products where agents need their own auth layer.
- You want a permissive MIT license for the full stack, not just the client SDK.

## Pick Hanko if

- You want the smallest possible passkey-only library with a tight scope.
- You have no agent story and passkey-first is exactly the feature you need.
- You are comfortable with AGPL for your backend auth service.

## Related pages

- [Compare overview](overview.md)
- [Passkeys (WebAuthn)](../guides/auth/passkeys.md)
- [Agent Identity](../concepts/agents.md)
