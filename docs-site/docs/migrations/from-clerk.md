---
title: From Clerk
description: Move a Clerk app to TheAuth. Maps ClerkProvider, clerkMiddleware, useAuth, and Organizations to TheAuth, with Next.js middleware sample and data export steps.
---

# From Clerk

Clerk is a hosted identity service with a strong Next.js story and paid tiers that scale with MAU. TheAuth is open source, self-hosted, and treats AI agents as a first-class entity next to users. The two trade-offs are real: you give up Clerk's hosted sign-in UI and org management console, you take back your data, your cookie domain, your rate limits, and your bill.

When the switch makes sense:

- You are hitting Clerk's MAU pricing tiers and the cost stops matching the value.
- Your product now needs AI agents as first-class entities, an MCP OAuth 2.1 server, or per-agent trust scoring. Clerk does not model any of that.
- You want full control over session cookies, token issuance, and audit logs.
- Compliance needs (GDPR export, self-hosted data residency) are easier with a local service.

When to wait:

- You rely heavily on Clerk's hosted sign-in / sign-up components and have no designer bandwidth to rebuild them. TheAuth ships headless building blocks, not a dashboard you drop in.
- You use Clerk's B2B Organizations extensively with their admin UI. TheAuth has an organization plugin but no hosted admin console yet.

## Concepts map

| Clerk | TheAuth |
|---|---|
| `clerkClient` (server) | instance from `createTheAuth({...})` |
| `<ClerkProvider>` | `<TheAuthProvider>` from `@glinr/theauth-react` |
| `useUser()` | `useUser()` from `@glinr/theauth-react` |
| `useAuth()` | `useSession()` + `useSignOut()` from `@glinr/theauth-react` |
| `useSession()` | `useSession()` from `@glinr/theauth-react` |
| `useSignIn()`, `useSignUp()` | `useSignIn()`, `useSignUp()` from `@glinr/theauth-react` |
| `auth()` in server components | `kavach.auth.getSession()` using the request cookies |
| `currentUser()` | `kavach.auth.getUser()` using the request cookies |
| `clerkMiddleware()` | No drop-in. Read the session cookie in your own `middleware.ts` (sample below). |
| `app/api/webhooks/clerk/route.ts` | Not applicable. User events come from your database or the Kavach event hooks. |
| Hosted sign-in at `/sign-in` | Build your own page against `useSignIn()`. |
| Hosted org switcher | Build your own against the `organization` plugin. |
| JWT templates | `jwt` plugin with claim customization. |
| Clerk backend SDK `@clerk/backend` | Kavach server instance directly. |
| `Organization`, `Membership` | `organization` plugin (same model, similar shape). |

## Middleware replacement

Clerk's `clerkMiddleware()` reads the `__session` cookie from Clerk's CDN. TheAuth reads your own session cookie:

```ts
// middleware.ts
import { NextRequest, NextResponse } from 'next/server';
import { kavach } from './lib/kavach';

export async function middleware(req: NextRequest) {
  const sessionCookie = req.cookies.get('kavach_session')?.value;

  if (!sessionCookie && req.nextUrl.pathname.startsWith('/dashboard')) {
    return NextResponse.redirect(new URL('/login', req.url));
  }

  try {
    const session = await kavach.auth.verifySession(sessionCookie!);
    const requestHeaders = new Headers(req.headers);
    requestHeaders.set('x-user-id', session.userId);
    return NextResponse.next({ request: { headers: requestHeaders } });
  } catch {
    return NextResponse.redirect(new URL('/login', req.url));
  }
}

export const config = { matcher: ['/dashboard/:path*', '/api/:path*'] };
```

## Data export from Clerk

Clerk exports users via their backend SDK:

```typescript
import Clerk from '@clerk/backend';

const clerk = Clerk({ secretKey: process.env.CLERK_SECRET_KEY });

// Paginate through all users
let offset = 0;
const limit = 100;
const allUsers: ClerkUser[] = [];

while (true) {
  const page = await clerk.users.getUserList({ limit, offset });
  allUsers.push(...page.data);
  if (page.data.length < limit) break;
  offset += limit;
}

// Write to a JSON file for import
await fs.writeFile('clerk-users.json', JSON.stringify(allUsers, null, 2));
```

Then seed the users into TheAuth:

```typescript
import { kavach } from './lib/kavach';

for (const clerkUser of allUsers) {
  await kavach.db.insert(users).values({
    id: clerkUser.id,
    email: clerkUser.emailAddresses[0]?.emailAddress ?? '',
    name: `${clerkUser.firstName ?? ''} ${clerkUser.lastName ?? ''}`.trim(),
    emailVerified: clerkUser.emailAddresses[0]?.verification?.status === 'verified',
    createdAt: new Date(clerkUser.createdAt),
    updatedAt: new Date(clerkUser.updatedAt),
  }).onConflictDoNothing();
}
```

## Legacy password hashes

If users have passwords in Clerk, they use bcrypt. Configure TheAuth to accept them during a transition period:

```ts
import { createTheAuth } from '@glinr/theauth';
import { compare as bcryptCompare } from 'bcrypt';

export const kavach = await createTheAuth({
  database: { provider: 'postgres', url: process.env.DATABASE_URL! },
  secret: process.env.THEAUTH_SECRET!,
  baseUrl: process.env.AUTH_BASE_URL!,
  emailAndPassword: {
    enabled: true,
    verifyLegacyHash: async ({ storedHash, password }) => {
      if (!storedHash.startsWith('$2')) return false;
      return bcryptCompare(password, storedHash);
    },
  },
});
```

On a successful legacy verify, TheAuth rehashes the password with PBKDF2 and overwrites the stored value. After 30-60 days, drop the `verifyLegacyHash` hook.

## Rollout strategy

Keep Clerk wired up on a different subdomain while you roll out:

```ts
// middleware.ts (Next.js)
import { NextRequest, NextResponse } from 'next/server';

export function middleware(req: NextRequest) {
  const userHint = req.cookies.get('migration_cohort')?.value ?? '';
  const onKavach = userHint === 'kavach' || hashBucket(userHint) < Number(process.env.THEAUTH_ROLLOUT ?? '0');

  if (onKavach) {
    return NextResponse.next();
  }

  const url = new URL(req.nextUrl.pathname + req.nextUrl.search, 'https://legacy.example.com');
  return NextResponse.redirect(url);
}

function hashBucket(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return h % 100;
}
```

Start at `THEAUTH_ROLLOUT=10`, watch error rates and sign-in conversions, raise to 100 over a week or two.

## FAQ

**Will my users be signed out on cutover day?**
Yes, unless you run a side-by-side rollout. Clerk session cookies cannot be verified without Clerk, so TheAuth cannot accept them. A one-time sign-in is the simplest story.

**Do OAuth tokens survive the migration?**
No. Clerk does not export live OAuth access or refresh tokens. Users re-authorize the provider on first sign-in after migration.

**Does TheAuth have an equivalent of Clerk's Organizations UI?**
Not hosted. The `organization` plugin has the same model (organization, membership, role). You build the UI.

**What about Clerk's impersonation features?**
The `admin` plugin ships impersonation with TTL.

**I use Clerk's JWT templates. What replaces them?**
The `jwt` plugin exposes a `customClaims` callback that runs at token issuance.

## Related pages

- [Compare: vs Clerk and Auth0](../compare/vs-paid.md)
- [From better-auth](from-better-auth.md)
- [GDPR](../security/gdpr.md)
- [Agent Identity](../concepts/agents.md)
