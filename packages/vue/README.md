# @glinr/theauth-vue

[npm](https://www.npmjs.com/package/@glinr/theauth-vue) · [Source](https://github.com/glincker/theauth/tree/main/packages/vue) · [Docs](https://docs.theauth.dev/vue) · [All packages](https://github.com/glincker/theauth#packages)

Vue plugin and composables for theAuth authentication.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-vue?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-vue)

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Install

```bash
npm install @glinr/theauth-vue
```

## Usage

Register the plugin in your Vue app, then use composables in any component.

```ts
// main.ts
import { createApp } from 'vue';
import { createTheAuthPlugin } from '@glinr/theauth-vue';
import App from './App.vue';

const app = createApp(App);

app.use(createTheAuthPlugin({
  apiUrl: 'https://auth.yourapp.com',
  tenantId: 'your-tenant-id',
}));

app.mount('#app');
```

```vue
<script setup lang="ts">
import { useSession, useUser, useSignIn, useSignOut } from '@glinr/theauth-vue';

const { session, isLoading } = useSession();
const { user } = useUser();
const { signIn } = useSignIn();
const { signOut } = useSignOut();
</script>

<template>
  <div v-if="!isLoading">
    <p v-if="user">Welcome, {{ user.email }}</p>
    <button v-if="session" @click="signOut">Sign out</button>
  </div>
</template>
```

## Exports

- `createTheAuthPlugin`: Vue plugin factory
- `useSession`: current session and loading state
- `useUser`: authenticated user object
- `useSignIn`: sign-in composable
- `useSignOut`: sign-out composable
- `useSignUp`: sign-up composable
- `useAgents`: manage AI agents for the current user

## Docs

[https://docs.theauth.dev](https://docs.theauth.dev)

## Community

[![Discord](https://img.shields.io/discord/829168897080557579?style=flat-square&logo=discord&logoColor=white&label=discord&color=5865F2)](https://discord.gg/Ar5pcaZB99)

Questions and help in the `#theauth` forum on the [GLINR Discord](https://discord.gg/Ar5pcaZB99).

## License

MIT
