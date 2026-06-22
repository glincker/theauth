---
title: Test Utilities
description: Test auth-dependent code without a database using @glinr/theauth-test-utils. Provides entity factories, in-memory mock auth server, and per-request user overrides.
---

# Test Utilities

`@glinr/theauth-test-utils` provides factories, mock servers, and assertion helpers so you can test auth-dependent code without a real database or network.

## Install

```bash
pnpm add -D @glinr/theauth-test-utils
```

## Factories

Factory functions create realistic mock entities with sensible defaults. Pass overrides for any fields relevant to the test.

```ts
import {
  createMockUser,
  createMockSession,
  createMockAgent,
  createMockPermission,
} from '@glinr/theauth-test-utils';

const user = createMockUser({ email: 'alice@example.com' });
const session = createMockSession({ user });
const agent = createMockAgent({ type: 'service', permissions: [] });
const perm = createMockPermission({ resource: 'files', actions: ['read', 'write'] });
```

Each call generates unique IDs, so you can create multiple entities in the same test without collisions.

## Mock auth server

`createMockAuthServer` returns an in-memory `AuthAdapter` implementation with zero network or database calls. Use it in server-side unit tests that exercise code paths calling `resolveUser`, `getUser`, or `syncUser`.

```ts
import { createMockAuthServer, createMockUser } from '@glinr/theauth-test-utils';

const server = createMockAuthServer();
const user = createMockUser();

server.addUser(user);
server.setActiveUser(user.id);

const resolved = await server.resolveUser(new Request('https://example.com'));
// resolved.id === user.id
```

## Per-request user override

Set the `x-mock-kavach-user-id` header on a `Request` to override the active user for that specific request only, without calling `setActiveUser`:

```ts
import { MOCK_USER_ID_HEADER } from '@glinr/theauth-test-utils';

const req = new Request('https://example.com', {
  headers: { [MOCK_USER_ID_HEADER]: user.id },
});
```

## In-memory kavach instance

For integration tests, use SQLite in-memory mode with `createKavach`:

```ts
import { createKavach } from '@glinr/theauth';

const kavach = createKavach({
  database: { provider: 'sqlite', url: ':memory:' },
  agents: { enabled: true, auditAll: true },
});

// Tests run against a fresh in-memory database
const agent = await kavach.agent.create({
  ownerId: 'test-user',
  name: 'test-agent',
  type: 'autonomous',
  permissions: [{ resource: 'mcp:*', actions: ['read'] }],
});

const result = await kavach.authorize(agent.id, {
  action: 'read',
  resource: 'mcp:github:repos',
});

expect(result.allowed).toBe(true);
```

## Related pages

- [Error Codes](errors.md)
- [Agent Identity](../concepts/agents.md)
