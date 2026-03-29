# @kavachos/vue

Vue plugin and composables for KavachOS authentication.

[![npm](https://img.shields.io/npm/v/@kavachos/vue?style=flat-square)](https://www.npmjs.com/package/@kavachos/vue)

## Install

```bash
npm install @kavachos/vue
```

## Usage

Register the plugin in your Vue app, then use composables in any component.

```ts
// main.ts
import { createApp } from 'vue';
import { createKavachPlugin } from '@kavachos/vue';
import App from './App.vue';

const app = createApp(App);

app.use(createKavachPlugin({
  apiUrl: 'https://auth.yourapp.com',
  tenantId: 'your-tenant-id',
}));

app.mount('#app');
```

```vue
<script setup lang="ts">
import { useSession, useUser, useSignIn, useSignOut } from '@kavachos/vue';

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

- `createKavachPlugin` — Vue plugin factory
- `useSession` — current session and loading state
- `useUser` — authenticated user object
- `useSignIn` — sign-in composable
- `useSignOut` — sign-out composable
- `useSignUp` — sign-up composable
- `useAgents` — manage AI agents for the current user

## Docs

[https://docs.kavachos.com](https://docs.kavachos.com)

## License

MIT
