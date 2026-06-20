# @theauth/electron

Electron integration for TheAuth: secure storage, OAuth windows, and IPC bridge.

[![npm](https://img.shields.io/npm/v/@theauth/electron?style=flat-square)](https://www.npmjs.com/package/@theauth/electron)

## Install

```bash
npm install @theauth/electron
```

## Usage

Set up the IPC bridge in the main process, then use the provider in the renderer.

```ts
// main.ts (main process)
import { setupKavachIpc, createElectronStorage } from '@theauth/electron';

const storage = createElectronStorage({ encryptionKey: process.env.STORAGE_KEY });
setupKavachIpc({ storage });
```

```tsx
// renderer.tsx
import { ElectronKavachProvider, useElectronKavachContext } from '@theauth/electron';

function App() {
  return (
    <ElectronKavachProvider apiUrl="https://auth.yourapp.com" tenantId="your-tenant-id">
      <MainWindow />
    </ElectronKavachProvider>
  );
}
```

```ts
// OAuth login from renderer
import { openOAuthWindow } from '@theauth/electron';

const result = await openOAuthWindow({ provider: 'google', redirectUri: 'kavach://oauth' });
```

## Exports

- `ElectronKavachProvider` / `ElectronKavachContext` / `useElectronKavachContext`: renderer-side provider
- `createElectronStorage`: encrypted keychain-backed storage
- `createMemoryStorage`: in-memory storage for testing
- `setupKavachIpc` / `createIpcStorage` / `KAVACH_IPC_CHANNELS`: main-process IPC setup
- `openOAuthWindow`: opens a managed OAuth popup window

## Docs

[https://docs.theauth.com](https://docs.theauth.com)

## License

MIT
