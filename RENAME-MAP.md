# Rename Map: Kavach* / Auth* to TheAuth*

All old names remain exported as `@deprecated` aliases. Removal target: a future major version.

The rename happened in two steps. `Kavach*` (the original name) was first renamed to `Auth*`, then the project settled on `TheAuth*` as the final, canonical name. Both `Auth*` and `Kavach*` still work, they just point at the same `TheAuth*` implementation under the hood.

## Core (`@glinr/theauth`)

| Old name (deprecated) | Intermediate name (deprecated) | Canonical name |
|---|---|---|
| `createKavach` | `createAuth` | `createTheAuth` |
| `Kavach` | `Auth` | `TheAuth` |
| `KavachConfig` | `AuthConfig` | `TheAuthConfig` |
| `KavachInstance` | `AuthInstance` | `TheAuthInstance` |
| `KavachHooks` | `AuthHooks` | `TheAuthHooks` |
| `KavachPlugin` | `AuthPlugin` | `TheAuthPlugin` |
| `KavachError` | `AuthError` | `TheAuthError` |
| `KAVACH_AGENT_CREDENTIAL` | `AUTH_AGENT_CREDENTIAL` | `THEAUTH_AGENT_CREDENTIAL` |
| `KAVACH_PERMISSION_CREDENTIAL` | `AUTH_PERMISSION_CREDENTIAL` | `THEAUTH_PERMISSION_CREDENTIAL` |
| `KAVACH_DELEGATION_CREDENTIAL` | `AUTH_DELEGATION_CREDENTIAL` | `THEAUTH_DELEGATION_CREDENTIAL` |

## Client (`@glinr/theauth-client`)

| Old name (deprecated) | Intermediate name (deprecated) | Canonical name |
|---|---|---|
| `KavachApiError` | `AuthApiError` | `TheAuthApiError` |
| `KavachClientOptions` | `AuthClientOptions` | `TheAuthClientOptions` |
| `KavachClient` | `AuthClient` | `TheAuthClient` |
| `createKavachClient` | `createAuthClient` | `createTheAuthClient` |

## React (`@glinr/theauth-react`)

| Old name (deprecated) | Intermediate name (deprecated) | Canonical name |
|---|---|---|
| `KavachUser` | `AuthUser` | `TheAuthUser` |
| `KavachSession` | `AuthSession` | `TheAuthSession` |
| `KavachAgent` | `AuthAgent` | `TheAuthAgent` |
| `KavachPermission` | `AuthPermission` | `TheAuthPermission` |
| `KavachContextValue` | `AuthContextValue` | `TheAuthContextValue` |
| `KavachContext` | `AuthContext` | `TheAuthContext` |
| `KavachProvider` | `AuthProvider` | `TheAuthProvider` |
| `KavachProviderProps` | `AuthProviderProps` | `TheAuthProviderProps` |
| `useKavachContext` | `useAuthContext` | `useTheAuthContext` |

## Vue (`@glinr/theauth-vue`)

| Old name (deprecated) | Intermediate name (deprecated) | Canonical name |
|---|---|---|
| `KAVACH_KEY` | `AUTH_KEY` | `THEAUTH_KEY` |
| `KavachPluginOptions` | `AuthPluginOptions` | `TheAuthPluginOptions` |
| `createKavachPlugin` | `createAuthPlugin` | `createTheAuthPlugin` |
| `KavachUser` | `AuthUser` | `TheAuthUser` |
| `KavachSession` | `AuthSession` | `TheAuthSession` |
| `KavachAgent` | `AuthAgent` | `TheAuthAgent` |
| `KavachPermission` | `AuthPermission` | `TheAuthPermission` |
| `KavachContextValue` | `AuthContextValue` | `TheAuthContextValue` |

## Svelte (`@glinr/theauth-svelte`)

| Old name (deprecated) | Intermediate name (deprecated) | Canonical name |
|---|---|---|
| `createKavachClient` | `createAuthClient` | `createTheAuthClient` |
| `KavachClientOptions` | `AuthClientOptions` | `TheAuthClientOptions` |
| `KavachClient` | `AuthClient` | `TheAuthClient` |
| `KavachUser` | `AuthUser` | `TheAuthUser` |
| `KavachSession` | `AuthSession` | `TheAuthSession` |
| `KavachAgent` | `AuthAgent` | `TheAuthAgent` |
| `KavachPermission` | `AuthPermission` | `TheAuthPermission` |

## Expo (`@glinr/theauth-expo`)

| Old name (deprecated) | Intermediate name (deprecated) | Canonical name |
|---|---|---|
| `KavachStorage` | `AuthStorage` | `TheAuthStorage` |
| `KavachExpoConfig` | `AuthExpoConfig` | `TheAuthExpoConfig` |
| `KavachContextValue` | `AuthContextValue` | `TheAuthContextValue` |
| `KavachExpoContext` | `AuthExpoContext` | `TheAuthExpoContext` |
| `KavachExpoProvider` | `AuthExpoProvider` | `TheAuthExpoProvider` |
| `KavachExpoProviderProps` | `AuthExpoProviderProps` | `TheAuthExpoProviderProps` |
| `useKavachContext` | `useAuthContext` | `useTheAuthContext` |
| `KavachUser` | `AuthUser` | `TheAuthUser` |
| `KavachSession` | `AuthSession` | `TheAuthSession` |
| `KavachAgent` | `AuthAgent` | `TheAuthAgent` |
| `KavachPermission` | `AuthPermission` | `TheAuthPermission` |

## Dashboard (`@glinr/theauth-dashboard`)

| Old name (deprecated) | Intermediate name (deprecated) | Canonical name |
|---|---|---|
| `KavachSettings` | `AuthSettings` | `TheAuthSettings` |
| `KavachApiClient` | `AuthApiClient` | `TheAuthApiClient` |
| `KavachDashboard` | `AuthDashboard` | `TheAuthDashboard` |

## Email auth (`@glinr/theauth-email`)

| Old name (deprecated) | Intermediate name (deprecated) | Canonical name |
|---|---|---|
| `KavachEmailError` | `AuthEmailError` | `TheAuthEmailError` |

## Adapters

### Next.js (`@glinr/theauth-nextjs`)

| Old name (deprecated) | Intermediate name (deprecated) | Canonical name |
|---|---|---|
| `KavachNextjsOptions` | `AuthNextjsOptions` | `TheAuthNextjsOptions` |
| `KavachNextjsHandlers` | `AuthNextjsHandlers` | `TheAuthNextjsHandlers` |
| `kavachNextjs` | `authNextjs` | `theAuthNextjs` |

### NestJS (`@glinr/theauth-nestjs`)

| Old name (deprecated) | Intermediate name (deprecated) | Canonical name |
|---|---|---|
| `KavachNestjsOptions` | `AuthNestjsOptions` | `TheAuthNestjsOptions` |
| `buildKavachRouter` | `buildAuthRouter` | `buildTheAuthRouter` |
| `kavachMiddleware` | `authMiddleware` | `theAuthMiddleware` |
| `KavachModuleOptions` | `AuthModuleOptions` | `TheAuthModuleOptions` |
| `KavachModule` | `AuthModule` | `TheAuthModule` |

### TanStack Start (`@glinr/theauth-tanstack`)

| Old name (deprecated) | Intermediate name (deprecated) | Canonical name |
|---|---|---|
| `KavachTanStackOptions` | `AuthTanStackOptions` | `TheAuthTanStackOptions` |
| `KavachTanStackHandlers` | `AuthTanStackHandlers` | `TheAuthTanStackHandlers` |
| `kavachTanStack` | `authTanStack` | `theAuthTanStack` |

### SvelteKit (`@glinr/theauth-sveltekit`)

| Old name (deprecated) | Intermediate name (deprecated) | Canonical name |
|---|---|---|
| `KavachSvelteKitOptions` | `AuthSvelteKitOptions` | `TheAuthSvelteKitOptions` |
| `KavachSvelteKitHandlers` | `AuthSvelteKitHandlers` | `TheAuthSvelteKitHandlers` |
| `kavachSvelteKit` | `authSvelteKit` | `theAuthSvelteKit` |

### Astro (`@glinr/theauth-astro`)

| Old name (deprecated) | Intermediate name (deprecated) | Canonical name |
|---|---|---|
| `KavachAstroOptions` | `AuthAstroOptions` | `TheAuthAstroOptions` |
| `KavachAstroHandlers` | `AuthAstroHandlers` | `TheAuthAstroHandlers` |
| `kavachAstro` | `authAstro` | `theAuthAstro` |

### Nuxt (`@glinr/theauth-nuxt`)

| Old name (deprecated) | Intermediate name (deprecated) | Canonical name |
|---|---|---|
| `KavachNuxtOptions` | `AuthNuxtOptions` | `TheAuthNuxtOptions` |
| `kavachNuxt` | `authNuxt` | `theAuthNuxt` |

### Fastify (`@glinr/theauth-fastify`)

| Old name (deprecated) | Intermediate name (deprecated) | Canonical name |
|---|---|---|
| `KavachFastifyOptions` | `AuthFastifyOptions` | `TheAuthFastifyOptions` |
| `kavachFastify` | `authFastify` | `theAuthFastify` |

### SolidStart (`@glinr/theauth-solidstart`)

| Old name (deprecated) | Intermediate name (deprecated) | Canonical name |
|---|---|---|
| `KavachSolidStartOptions` | `AuthSolidStartOptions` | `TheAuthSolidStartOptions` |
| `KavachSolidStartHandlers` | `AuthSolidStartHandlers` | `TheAuthSolidStartHandlers` |
| `kavachSolidStart` | `authSolidStart` | `theAuthSolidStart` |

### Prisma (`@glinr/theauth-prisma`)

| Old name (deprecated) | Intermediate name (deprecated) | Canonical name |
|---|---|---|
| `KavachPrismaAdapter` | `AuthPrismaAdapter` | `TheAuthPrismaAdapter` |

## Migration guide

Replace all `Kavach*` or `Auth*` identifiers with their `TheAuth*` equivalents using the table above. Your editor's find-and-replace or a codemod script is sufficient -- no logic changes are required. The function signatures, return types, and runtime behavior are identical.

Example:

```typescript
// Before
import { createKavach, KavachConfig } from "@glinr/theauth";
const auth = await createKavach(config);

// Also deprecated (intermediate name, skip straight to TheAuth* instead)
import { createAuth, AuthConfig } from "@glinr/theauth";
const auth = await createAuth(config);

// After
import { createTheAuth, TheAuthConfig } from "@glinr/theauth";
const auth = await createTheAuth(config);
```
