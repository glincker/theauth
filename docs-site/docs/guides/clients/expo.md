---
title: Expo / React Native
description: Wire TheAuth auth into React Native and Expo apps with @glinr/theauth-expo. Stores tokens in AsyncStorage or SecureStore and authenticates via Authorization header.
---

# Expo / React Native

`@glinr/theauth-expo` brings TheAuth auth to React Native and Expo apps. It stores session tokens in any storage adapter you choose (AsyncStorage, SecureStore, or your own) and sends them via `Authorization` header rather than cookies.

## Installation

```bash
pnpm add @glinr/theauth-expo
```

You also need a storage library:

=== "AsyncStorage"
    ```bash
    npx expo install @react-native-async-storage/async-storage
    ```
=== "SecureStore (encrypted)"
    ```bash
    npx expo install expo-secure-store
    ```

## Setup

### Wrap your app

```tsx
// app/_layout.tsx (Expo Router) or App.tsx
import { KavachExpoProvider } from '@glinr/theauth-expo';
import AsyncStorage from '@react-native-async-storage/async-storage';

export default function RootLayout() {
  return (
    <KavachExpoProvider
      config={{
        baseUrl: 'https://api.yourapp.com/api/kavach',
        storage: AsyncStorage,
      }}
    >
      {/* your app */}
    </KavachExpoProvider>
  );
}
```

### With SecureStore

```tsx
import * as SecureStore from 'expo-secure-store';

const storage = {
  getItem: (key: string) => SecureStore.getItemAsync(key),
  setItem: (key: string, value: string) => SecureStore.setItemAsync(key, value),
  removeItem: (key: string) => SecureStore.deleteItemAsync(key),
};

<KavachExpoProvider config={{ baseUrl: '...', storage }}>
  {/* your app */}
</KavachExpoProvider>
```

## Hooks

The same hook names as `@glinr/theauth-react` work in Expo:

```tsx
import { useUser, useSignIn, useSignOut } from '@glinr/theauth-expo';

function LoginScreen() {
  const { signIn, isLoading, error } = useSignIn();

  async function handleLogin() {
    await signIn({ email: 'user@example.com', password: 'password' });
  }

  return (
    <Button onPress={handleLogin} title="Sign in" />
  );
}
```

## OAuth with WebBrowser

For social OAuth in Expo, use `expo-web-browser` to open the authorization URL:

```tsx
import * as WebBrowser from 'expo-web-browser';
import { useOAuth } from '@glinr/theauth-expo';

function GoogleSignIn() {
  const { getAuthUrl, handleCallback } = useOAuth('google');

  async function signInWithGoogle() {
    const authUrl = await getAuthUrl();
    const result = await WebBrowser.openAuthSessionAsync(authUrl, 'yourapp://auth');
    if (result.type === 'success') {
      await handleCallback(result.url);
    }
  }

  return <Button onPress={signInWithGoogle} title="Sign in with Google" />;
}
```

## Related pages

- [React](react.md)
- [Electron](electron.md)
- [Configuration](../../reference/configuration.md)
