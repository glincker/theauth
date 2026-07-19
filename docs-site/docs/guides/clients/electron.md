---
title: Electron
description: Add auth to Electron apps via createKavachElectron. Covers OS keychain token storage, OAuth popup windows, IPC bridge, and automatic token refresh.
---

# Electron

`@glinr/theauth-electron` provides secure auth for Electron desktop apps with encrypted token storage, OAuth popup windows, and IPC bridge for renderer-to-main communication.

## Install

```bash
pnpm add @glinr/theauth-electron
```

## Setup (main process)

```ts
import { createKavachElectron } from '@glinr/theauth-electron';
import { ipcMain } from 'electron';

const kavach = createKavachElectron({
  baseUrl: 'https://api.myapp.com/api/kavach',
  appName: 'MyApp',
});

// Register IPC handlers so the renderer can call auth methods
kavach.registerIpcHandlers(ipcMain);
```

Tokens are stored in the OS keychain (Keychain on macOS, Credential Manager on Windows, libsecret on Linux). They are never written to disk in plaintext.

## Usage (renderer process)

```ts
import { useKavachElectron } from '@glinr/theauth-electron/renderer';

const { signIn, signOut, getSession, getUser } = useKavachElectron();

const session = await getSession();
if (!session) {
  await signIn('google'); // Opens OAuth popup window
}
```

## OAuth popup windows

When the user initiates an OAuth flow, `@glinr/theauth-electron` opens a `BrowserWindow` at the authorization URL, waits for the redirect to your app's deep link, and exchanges the code for tokens automatically. The popup is managed by the main process; the renderer just awaits the result.

## Token refresh

Tokens are refreshed automatically in the background before they expire. Configure the refresh buffer:

```ts
const kavach = createKavachElectron({
  baseUrl: 'https://api.myapp.com/api/kavach',
  appName: 'MyApp',
  refreshBufferSeconds: 300, // refresh 5 minutes before expiry
});
```

## Related pages

- [React](react.md)
- [Expo / React Native](expo.md)
- [Configuration](../../reference/configuration.md)
