---
"@glinr/theauth-expo": minor
---

Passkeys for the Expo client. `signInWithPasskey`, `registerPasskey` and the `usePasskeys` hook take a platform authenticator (`react-native-passkey` works as is) through `config.passkeys`. A new `config.fetch` routes every request through your own fetch, for DPoP proofs or certificate pinning.
