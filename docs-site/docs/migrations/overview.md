---
title: Migration Overview
description: Pick a migration guide for your current auth setup. Covers moving from better-auth, Clerk, the better-auth agent plugin, and Auth0 to TheAuth.
---

# Migration Overview

Pick the guide that matches your current setup.

| Current setup | Guide |
|---|---|
| better-auth | [From better-auth](from-better-auth.md) |
| better-auth agent plugin | [From better-auth agent plugin](from-better-auth-agent-plugin.md) |
| Clerk | [From Clerk](from-clerk.md) |
| Auth0 | [From Auth0](from-auth0.md) |

## General migration approach

1. Keep your existing auth system running during migration. TheAuth does not need to replace it all at once.
2. Install and configure TheAuth alongside the existing library.
3. Migrate agent-related code first (the unique value of TheAuth).
4. Optionally migrate human auth code last, or not at all (TheAuth integrates with external auth providers via adapters).
5. Once cutover is confirmed, remove the old auth library.

## Staying on your current human auth provider

If you use Clerk, Auth.js, or better-auth for human sign-in and are satisfied with it, you can keep using it. TheAuth integrates with external auth providers by accepting a user ID. Your existing human auth resolves the user; TheAuth takes over for agent identity.

```typescript
// Example: keep Clerk for human auth, use TheAuth for agents
import { auth } from '@clerk/nextjs/server';
import { kavach } from '@/lib/kavach';

export async function createAgent(userId: string) {
  // userId comes from Clerk; TheAuth doesn't care where it originated
  return kavach.agent.create({
    ownerId: userId,
    name: 'my-agent',
    type: 'autonomous',
    permissions: [{ resource: 'mcp:*', actions: ['read'] }],
  });
}
```

## Related pages

- [From better-auth](from-better-auth.md)
- [From Clerk](from-clerk.md)
