# @kavachos/svelte

Svelte stores for KavachOS authentication.

[![npm](https://img.shields.io/npm/v/@kavachos/svelte?style=flat-square)](https://www.npmjs.com/package/@kavachos/svelte)

## Install

```bash
npm install @kavachos/svelte
```

## Usage

Create a client and stores at the top of your app, then subscribe in any component.

```ts
// lib/kavach.ts
import { createKavachClient, createAgentStore } from '@kavachos/svelte';

export const kavach = createKavachClient({
  apiUrl: 'https://auth.yourapp.com',
  tenantId: 'your-tenant-id',
});

export const agents = createAgentStore({ client: kavach });
```

```svelte
<script>
  import { kavach, agents } from '$lib/kavach';

  const { session, user } = kavach;
</script>

{#if $session}
  <p>Welcome, {$user?.email}</p>
  <button on:click={() => kavach.signOut()}>Sign out</button>
{:else}
  <button on:click={() => kavach.signIn({ email, password })}>Sign in</button>
{/if}
```

## Exports

- `createKavachClient` — creates a reactive Svelte store client
- `createAgentStore` — creates a store for managing AI agents

## Docs

[https://docs.kavachos.com](https://docs.kavachos.com)

## License

MIT
