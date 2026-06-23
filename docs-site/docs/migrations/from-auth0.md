---
title: From Auth0
description: Port an Auth0 tenant to TheAuth. Maps tenants, M2M clients, Rules, and Actions to TheAuth equivalents with side-by-side code diffs and SQL migration steps.
---

# From Auth0

Auth0 is a hosted identity platform with a deep enterprise feature set: Rules, Actions, Hooks, Organizations, and Machine-to-Machine (M2M) clients. TheAuth is open source, self-hosted, and models AI agents as a first-class entity next to human users.

When the switch makes sense:

- Your M2M client count (or Auth0 MAU) has outgrown what the tier price pays for.
- You are building AI agents and Auth0's per-connection M2M model does not give you delegation chains, per-agent rate caps, trust scoring, or cost attribution.
- You want an MCP OAuth 2.1 server wired into the same auth instance rather than a second system.
- You need GDPR export, self-hosted data residency, or EU AI Act reporting on the same platform that issues your tokens.

When to wait:

- You rely on Auth0's Universal Login branding, device enrollment flow, or the Guardian MFA app. TheAuth ships headless building blocks, not a hosted page.
- Your Rules or Actions logic runs heavy third-party integrations (Okta, Duo, Risk signals). You can port that logic, but it is not a copy-paste job.
- You are on Enterprise with dedicated support SLAs.

## Concepts map

| Auth0 | TheAuth |
|---|---|
| Tenant | A `createAuth` instance. One per deployment. |
| Application (Regular Web, SPA, Native) | `@glinr/theauth-react`, `@glinr/theauth-vue`, etc., plus the framework adapter. |
| API (resource server) | The HTTP handler mounted via an adapter. Audience bound via the `mcp` config. |
| Machine-to-Machine client | `AgentIdentity` with `type: 'service'`. Scoped permissions, rotatable token, revocable. |
| Connection (database, social, enterprise) | OAuth provider in the `oauth` plugin config, or the built-in email/password flow. |
| Rule | Deprecated in Auth0 as well. Replace with a lifecycle hook on `createAuth` or a policy. |
| Action (`onExecutePostLogin`, etc.) | Lifecycle hooks: `onSignIn`, `onSignUp`, `beforeSession`, `afterSession`. |
| Organizations | `organization` plugin (same conceptual model). |
| Roles, Permissions | `rbac` + resource-pattern matching on permissions. |
| `authorize` endpoint | Built-in. PKCE S256 only. |
| Management API | Server-side instance methods directly, no separate API. |
| Refresh token rotation | On by default with the `jwtSession` and `refresh` plugins. |
| Tenant logs | Audit trail via `kavach.audit.query()` and the audit export. |
| Custom domain | Set `baseUrl` and the cookie config on `createAuth`. |

## Server setup

```ts
// lib/kavach.ts
import { createAuth } from '@glinr/theauth';
import { organization, rbac } from '@glinr/theauth/plugins';

export const kavach = await createAuth({
  database: { provider: 'postgres', url: process.env.DATABASE_URL! },
  secret: process.env.THEAUTH_SECRET!,
  baseUrl: process.env.AUTH_BASE_URL!, // e.g. https://auth.example.com
  emailAndPassword: { enabled: true },
  mcp: {
    issuer: process.env.AUTH_BASE_URL!,
    audience: process.env.API_BASE_URL!, // the resource server URL
  },
  plugins: [
    organization(),
    rbac(),
  ],
});
```

## M2M clients to agents

Auth0 M2M clients use client credentials flow. In TheAuth, replace them with `type: 'service'` agents:

=== "Before (Auth0 M2M)"
    ```typescript
    // Auth0: create M2M client in dashboard, then:
    const tokenRes = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        audience: API_AUDIENCE,
        grant_type: 'client_credentials',
      }),
    });
    const { access_token } = await tokenRes.json();
    ```
=== "After (TheAuth service agent)"
    ```typescript
    const serviceAgent = await kavach.agent.create({
      ownerId: 'system',
      name: 'reporting-service',
      type: 'service',
      permissions: [
        { resource: 'api:reports:*', actions: ['read'] },
      ],
    });

    // Use agent.token as the Bearer credential
    const result = await kavach.authorizeByToken(serviceAgent.token, {
      action: 'read',
      resource: 'api:reports:q4-2025',
    });
    ```

## Rules to lifecycle hooks

Auth0 Rules are JavaScript functions that run in the auth pipeline. TheAuth lifecycle hooks are typed TypeScript callbacks:

=== "Before (Auth0 Rule)"
    ```js
    function addRolesToToken(user, context, callback) {
      const assignedRoles = (context.authorization || {}).roles;
      const idTokenClaims = context.idToken || {};
      idTokenClaims['https://myapp.com/roles'] = assignedRoles;
      context.idToken = idTokenClaims;
      callback(null, user, context);
    }
    ```
=== "After (TheAuth hook)"
    ```typescript
    const kavach = await createAuth({
      // ...
      hooks: {
        onTokenIssue: async ({ userId, claims }) => {
          const roles = await db.query.roles.findMany({ where: eq(roles.userId, userId) });
          return { ...claims, 'https://myapp.com/roles': roles.map(r => r.name) };
        },
      },
    });
    ```

## Related pages

- [Compare: vs Clerk and Auth0](../compare/vs-paid.md)
- [From Clerk](from-clerk.md)
- [Agent Identity](../concepts/agents.md)
- [MCP Authorization](../concepts/mcp-authorization.md)
