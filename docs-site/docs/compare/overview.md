---
title: Compare TheAuth
description: Side-by-side breakdowns of TheAuth against better-auth, Hanko, Casdoor, and paid platforms.
---

# Compare TheAuth

Auth is a crowded space. These pages are meant to help you pick the right tool, not sell you on any particular one. If a competitor does something better, we say so.

| Comparison | Summary |
|---|---|
| [vs better-auth](vs-better-auth.md) | Both are MIT TypeScript libraries with a broad OAuth provider list. The split is agent primitives: better-auth treats agents as OAuth clients; TheAuth makes them first-class entities with delegation, ephemeral sessions, trust scoring, and compliance exports. |
| [vs Hanko](vs-hanko.md) | Hanko is a passkey-first library with an AGPL backend. If passkeys are your entire auth story and you have no agent workloads, it is worth a look. If you need agent identity or RBAC, you will be building on top of it yourself. |
| [vs Casdoor](vs-casdoor.md) | Casdoor is a deployed Go IAM service with LDAP, CAS, and RADIUS support. It targets employee SSO in Go shops. TheAuth is a library, not a service, and it is built for agent-native TypeScript apps. |
| [vs Clerk and Auth0](vs-paid.md) | Clerk and Auth0 are polished, fast to start, and expensive at scale. They are also closed-source. This page covers the open-source vs. managed tradeoff without reproducing any pricing tables. |
