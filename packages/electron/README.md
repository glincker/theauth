# @glinr/theauth-electron

Electron integration for TheAuth: secure storage, OAuth windows, and IPC bridge.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-electron?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-electron)

## Install

```bash
npm install @glinr/@glinr/theauth-electron
```

## Usage

Set up the IPC bridge in the main process, then use the provider in the renderer.

```ts
// main.ts (main process)
import { setupTheAuthIpc, createElectronStorage } from '@glinr/theauth-electron';

const storage = createElectronStorage({ encryptionKey: process.env.STORAGE_KEY });
setupTheAuthIpc({ storage });
```

```tsx
// renderer.tsx
import { ElectronTheAuthProvider, useElectronTheAuthContext } from '@glinr/theauth-electron';

function App() {
  return (
    <ElectronTheAuthProvider apiUrl="https://auth.yourapp.com" tenantId="your-tenant-id">
      <MainWindow />
    </ElectronTheAuthProvider>
  );
}
```

```ts
// OAuth login from renderer
import { openOAuthWindow } from '@glinr/theauth-electron';

const result = await openOAuthWindow({ provider: 'google', redirectUri: 'kavach://oauth' });
```

## Exports

- `ElectronTheAuthProvider` / `ElectronTheAuthContext` / `useElectronTheAuthContext`: renderer-side provider (formerly `ElectronKavach*`, still exported as deprecated aliases)
- `createElectronStorage`: encrypted keychain-backed storage
- `createMemoryStorage`: in-memory storage for testing
- `setupTheAuthIpc` / `createIpcStorage` / `THEAUTH_IPC_CHANNELS`: main-process IPC setup (formerly `setupKavachIpc` / `KAVACH_IPC_CHANNELS`, still exported as deprecated aliases)
- `openOAuthWindow`: opens a managed OAuth popup window

## Docs

[https://docs.theauth.dev](https://docs.theauth.dev)

## License

MIT
