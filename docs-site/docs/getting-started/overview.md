---
title: Overview
description: What TheAuth is, what problem it solves, and how it relates to human auth libraries.
---

# Overview

TheAuth is a TypeScript SDK for AI agent identity, permissions, delegation, and audit. It treats every AI agent as a first-class entity with its own bearer token, permission set, and audit trail.

## The problem

Most auth libraries are built for human users: sign-in forms, password resets, social OAuth, session cookies. AI agents are different. An agent does not sign in. It receives a bearer token, holds a set of permissions, and calls `authorize()` before acting on anything sensitive. Every decision needs to be logged for oversight and compliance.

General-purpose auth libraries do not model this. TheAuth does.

## What TheAuth is not

- It is not a replacement for your human auth library. Use Clerk, Auth.js, better-auth, or your own for login, signup, and social OAuth for human users.
- It is not a hosted service. It is an SDK you run on your own infrastructure.
- It is not a policy language. Permissions are structured TypeScript objects, not a custom DSL.

## Where it fits

```
Human user signs in       --> your auth library (Clerk, Auth.js, better-auth)
User creates an agent     --> TheAuth (kavach.agent.create)
Agent calls a tool        --> TheAuth (kavach.authorize)
Decision is logged        --> TheAuth (kavach_audit_logs)
```

TheAuth receives the user ID from your auth library and takes over from there.

## Core entities

**AgentIdentity** is the primary entity. Every AI agent gets one. It holds a bearer token (`kv_...` prefix), a set of permissions, and a status (`active`, `revoked`, `expired`).

**Permission** is a resource pattern, an action list, and optional constraints. Evaluated at every `authorize()` call.

**DelegationChain** lets one agent grant a subset of its permissions to another, with depth limits and expiry.

**AuditEntry** records every authorization decision: agent, user, resource, action, result, duration.

**TrustScore** is a 0-100 value computed from the audit log. It maps to five named levels that your application can use to gate behavior.

## Runtime support

TheAuth core uses Web Crypto only. No `node:crypto`. It runs on:

- Node.js 18+
- Cloudflare Workers
- Deno Deploy
- Vercel Edge Functions
- Bun

The `emailPassword` plugin uses `node:crypto` for scrypt. If you need that plugin on edge runtimes, swap the hasher for PBKDF2 via Web Crypto (see [Email and Password](../guides/auth/email-password.md)).

## Next steps

- [Installation](installation.md)
- [Quick Start](quick-start.md)
- [Core Concepts](../concepts/core-concepts.md)
