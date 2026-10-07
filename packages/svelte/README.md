# @glinr/theauth-svelte

[npm](https://www.npmjs.com/package/@glinr/theauth-svelte) · [Source](https://github.com/glincker/theauth/tree/main/packages/svelte) · [Docs](https://docs.theauth.dev/svelte) · [All packages](https://github.com/glincker/theauth#packages)

Svelte stores for theAuth authentication.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-svelte?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-svelte)

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Install

```bash
npm install @glinr/theauth-svelte
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

- `createTheAuthClient`: creates a reactive Svelte store client
- `createAgentStore`: creates a store for managing AI agents

## Docs

[https://docs.theauth.dev](https://docs.theauth.dev)

## Community

[![Discord](https://img.shields.io/discord/829168897080557579?style=flat-square&logo=discord&logoColor=white&label=discord&color=5865F2)](https://discord.gg/Ar5pcaZB99)

Questions and help in the `#theauth` forum on the [GLINR Discord](https://discord.gg/Ar5pcaZB99).

## License

MIT
