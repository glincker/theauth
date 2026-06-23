# Rename Map: Kavach* to Auth*

All old names remain exported as `@deprecated` aliases. Removal target: v3.0.

## Core (`@glinr/theauth`)

| Old name (deprecated) | New canonical name |
|---|---|
| `createKavach` | `createAuth` |
| `Kavach` | `Auth` |
| `KavachConfig` | `AuthConfig` |
| `KavachInstance` | `AuthInstance` |
| `KavachHooks` | `AuthHooks` |
| `KavachPlugin` | `AuthPlugin` |
| `KavachError` | `AuthError` |
| `KAVACH_AGENT_CREDENTIAL` | `AUTH_AGENT_CREDENTIAL` |
| `KAVACH_PERMISSION_CREDENTIAL` | `AUTH_PERMISSION_CREDENTIAL` |
| `KAVACH_DELEGATION_CREDENTIAL` | `AUTH_DELEGATION_CREDENTIAL` |

## Client (`@glinr/theauth-client`)

| Old name (deprecated) | New canonical name |
|---|---|
| `KavachApiError` | `AuthApiError` |
| `KavachClientOptions` | `AuthClientOptions` |
| `KavachClient` | `AuthClient` |
| `createKavachClient` | `createAuthClient` |

## React (`@glinr/theauth-react`)

| Old name (deprecated) | New canonical name |
|---|---|
| `KavachUser` | `AuthUser` |
| `KavachSession` | `AuthSession` |
| `KavachAgent` | `AuthAgent` |
| `KavachPermission` | `AuthPermission` |
| `KavachContextValue` | `AuthContextValue` |
| `KavachContext` | `AuthContext` |
| `KavachProvider` | `AuthProvider` |
| `KavachProviderProps` | `AuthProviderProps` |
| `useKavachContext` | `useAuthContext` |

## Vue (`@glinr/theauth-vue`)

| Old name (deprecated) | New canonical name |
|---|---|
| `KAVACH_KEY` | `AUTH_KEY` |
| `KavachPluginOptions` | `AuthPluginOptions` |
| `createKavachPlugin` | `createAuthPlugin` |

## Svelte (`@glinr/theauth-svelte`)

| Old name (deprecated) | New canonical name |
|---|---|
| `createKavachClient` | `createAuthClient` |

## Expo (`@glinr/theauth-expo`)

| Old name (deprecated) | New canonical name |
|---|---|
| `KavachStorage` | `AuthStorage` |
| `KavachExpoConfig` | `AuthExpoConfig` |
| `KavachContextValue` | `AuthContextValue` |
| `KavachExpoContext` | `AuthExpoContext` |
| `KavachExpoProvider` | `AuthExpoProvider` |
| `KavachExpoProviderProps` | `AuthExpoProviderProps` |
| `useKavachContext` | `useAuthContext` |

## Dashboard (`@glinr/theauth-dashboard`)

| Old name (deprecated) | New canonical name |
|---|---|
| `KavachSettings` | `AuthSettings` |
| `KavachApiClient` | `AuthApiClient` |
| `KavachDashboard` | `AuthDashboard` |

## Email auth (`@glinr/theauth-email`)

| Old name (deprecated) | New canonical name |
|---|---|
| `KavachEmailError` | `AuthEmailError` |

## Adapters

### Next.js (`@glinr/theauth-nextjs`)

| Old name (deprecated) | New canonical name |
|---|---|
| `KavachNextjsOptions` | `AuthNextjsOptions` |
| `KavachNextjsHandlers` | `AuthNextjsHandlers` |
| `kavachNextjs` | `authNextjs` |

### NestJS (`@glinr/theauth-nestjs`)

| Old name (deprecated) | New canonical name |
|---|---|
| `KavachNestjsOptions` | `AuthNestjsOptions` |
| `buildKavachRouter` | `buildAuthRouter` |
| `kavachMiddleware` | `authMiddleware` |
| `KavachModuleOptions` | `AuthModuleOptions` |
| `KavachModule` | `AuthModule` |

### TanStack Start (`@glinr/theauth-tanstack`)

| Old name (deprecated) | New canonical name |
|---|---|
| `KavachTanStackOptions` | `AuthTanStackOptions` |
| `KavachTanStackHandlers` | `AuthTanStackHandlers` |
| `kavachTanStack` | `authTanStack` |

### SvelteKit (`@glinr/theauth-sveltekit`)

| Old name (deprecated) | New canonical name |
|---|---|
| `KavachSvelteKitOptions` | `AuthSvelteKitOptions` |
| `KavachSvelteKitHandlers` | `AuthSvelteKitHandlers` |
| `kavachSvelteKit` | `authSvelteKit` |

### Astro (`@glinr/theauth-astro`)

| Old name (deprecated) | New canonical name |
|---|---|
| `KavachAstroOptions` | `AuthAstroOptions` |
| `KavachAstroHandlers` | `AuthAstroHandlers` |
| `kavachAstro` | `authAstro` |

### Nuxt (`@glinr/theauth-nuxt`)

| Old name (deprecated) | New canonical name |
|---|---|
| `KavachNuxtOptions` | `AuthNuxtOptions` |
| `kavachNuxt` | `authNuxt` |

### Fastify (`@glinr/theauth-fastify`)

| Old name (deprecated) | New canonical name |
|---|---|
| `KavachFastifyOptions` | `AuthFastifyOptions` |
| `kavachFastify` | `authFastify` |

### SolidStart (`@glinr/theauth-solidstart`)

| Old name (deprecated) | New canonical name |
|---|---|
| `KavachSolidStartOptions` | `AuthSolidStartOptions` |
| `KavachSolidStartHandlers` | `AuthSolidStartHandlers` |
| `kavachSolidStart` | `authSolidStart` |

### Prisma (`@glinr/theauth-prisma`)

| Old name (deprecated) | New canonical name |
|---|---|
| `KavachPrismaAdapter` | `AuthPrismaAdapter` |

## Migration guide

Replace all `Kavach*` identifiers with their `Auth*` equivalents using the table above. Your editor's find-and-replace or a codemod script is sufficient -- no logic changes are required. The function signatures, return types, and runtime behavior are identical.

Example:

```typescript
// Before
import { createKavach, KavachConfig } from "@glinr/theauth";
const auth = await createKavach(config);

// After
import { createAuth, AuthConfig } from "@glinr/theauth";
const auth = await createAuth(config);
```
