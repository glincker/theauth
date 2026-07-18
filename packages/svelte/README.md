# @glinr/theauth-svelte

Svelte stores for TheAuth authentication.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-svelte?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-svelte)

## Install

```bash
npm install @glinr/@glinr/theauth-svelte
```

## Usage

Create a client and stores at the top of your app, then subscribe in any component.

```ts
// lib/theauth.ts
import { createTheAuthClient, createAgentStore } from '@glinr/theauth-svelte';

export const auth = createTheAuthClient({
  apiUrl: 'https://auth.yourapp.com',
  tenantId: 'your-tenant-id',
});

export const agents = createAgentStore({ client: auth });
```

```svelte
<script>
  import { auth, agents } from '$lib/theauth';

  const { session, user } = auth;
</script>

{#if $session}
  <p>Welcome, {$user?.email}</p>
  <button on:click={() => auth.signOut()}>Sign out</button>
{:else}
  <button on:click={() => auth.signIn({ email, password })}>Sign in</button>
{/if}
```

## Exports

- `createTheAuthClient`: creates a reactive Svelte store client (formerly `createKavachClient`, still exported as a deprecated alias)
- `createAgentStore`: creates a store for managing AI agents

## Docs

[https://docs.theauth.dev](https://docs.theauth.dev)

## License

MIT
