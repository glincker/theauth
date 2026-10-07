# @glinr/theauth-electron

[npm](https://www.npmjs.com/package/@glinr/theauth-electron) · [Source](https://github.com/glincker/theauth/tree/main/packages/electron) · [Docs](https://docs.theauth.dev/electron) · [All packages](https://github.com/glincker/theauth#packages)

Electron integration for theAuth: secure storage, OAuth windows, and IPC bridge.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-electron?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-electron)

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Install

```bash
npm install @glinr/theauth-electron
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

const result = await openOAuthWindow({ provider: 'google', redirectUri: 'theauth://oauth' });
```

## Exports

- `ElectronTheAuthProvider` / `ElectronTheAuthContext` / `useElectronTheAuthContext`: renderer-side provider
- `createElectronStorage`: encrypted keychain-backed storage
- `createMemoryStorage`: in-memory storage for testing
- `setupTheAuthIpc` / `createIpcStorage` / `THEAUTH_IPC_CHANNELS`: main-process IPC setup
- `openOAuthWindow`: opens a managed OAuth popup window

## Docs

[https://docs.theauth.dev](https://docs.theauth.dev)

## Community

[![Discord](https://img.shields.io/discord/829168897080557579?style=flat-square&logo=discord&logoColor=white&label=discord&color=5865F2)](https://discord.gg/Ar5pcaZB99)

Questions and help in the `#theauth` forum on the [GLINR Discord](https://discord.gg/Ar5pcaZB99).

## License

MIT
