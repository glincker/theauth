# Rename map: Kavach* and Auth* to TheAuth*

The project was first called KavachOS, briefly used `Auth*` names, and settled on `TheAuth*`. This page lists every renamed export, and what else changed with the rename.

| Name family | `@glinr/theauth` 0.5.0 (on npm) | Next release (current `main`) |
|---|---|---|
| `Kavach*`, `createKavach`, `KAVACH_*` | Exported as deprecated aliases | **Removed** |
| `Auth*`, `createAuth`, `AUTH_*` | Exported as deprecated aliases | Still exported as deprecated aliases, removal in a future major version |
| `TheAuth*`, `createTheAuth`, `THEAUTH_*` | Canonical | Canonical |

If you are on 0.5.0 and still import a `Kavach*` name, switch before you upgrade. TypeScript will point at every use once the names are gone.

## Core (`@glinr/theauth`)

| Original name (removed) | Intermediate name (deprecated alias) | Canonical name |
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

| Original name (removed) | Intermediate name (deprecated alias) | Canonical name |
|---|---|---|
| `KavachApiError` | `AuthApiError` | `TheAuthApiError` |
| `KavachClientOptions` | `AuthClientOptions` | `TheAuthClientOptions` |
| `KavachClient` | `AuthClient` | `TheAuthClient` |
| `createKavachClient` | `createAuthClient` | `createTheAuthClient` |

## React (`@glinr/theauth-react`)

| Original name (removed) | Intermediate name (deprecated alias) | Canonical name |
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

| Original name (removed) | Intermediate name (deprecated alias) | Canonical name |
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

| Original name (removed) | Intermediate name (deprecated alias) | Canonical name |
|---|---|---|
| `createKavachClient` | `createAuthClient` | `createTheAuthClient` |
| `KavachClientOptions` | `AuthClientOptions` | `TheAuthClientOptions` |
| `KavachClient` | `AuthClient` | `TheAuthClient` |
| `KavachUser` | `AuthUser` | `TheAuthUser` |
| `KavachSession` | `AuthSession` | `TheAuthSession` |
| `KavachAgent` | `AuthAgent` | `TheAuthAgent` |
| `KavachPermission` | `AuthPermission` | `TheAuthPermission` |

## Expo (`@glinr/theauth-expo`)

| Original name (removed) | Intermediate name (deprecated alias) | Canonical name |
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

| Original name (removed) | Intermediate name (deprecated alias) | Canonical name |
|---|---|---|
| `KavachSettings` | `AuthSettings` | `TheAuthSettings` |
| `KavachApiClient` | `AuthApiClient` | `TheAuthApiClient` |
| `KavachDashboard` | `AuthDashboard` | `TheAuthDashboard` |

## Email auth (`@glinr/theauth-email`)

| Original name (removed) | Intermediate name (deprecated alias) | Canonical name |
|---|---|---|
| `KavachEmailError` | `AuthEmailError` | `TheAuthEmailError` |

## Adapters

### Next.js (`@glinr/theauth-nextjs`)

| Original name (removed) | Intermediate name (deprecated alias) | Canonical name |
|---|---|---|
| `KavachNextjsOptions` | `AuthNextjsOptions` | `TheAuthNextjsOptions` |
| `KavachNextjsHandlers` | `AuthNextjsHandlers` | `TheAuthNextjsHandlers` |
| `kavachNextjs` | `authNextjs` | `theAuthNextjs` |

### NestJS (`@glinr/theauth-nestjs`)

| Original name (removed) | Intermediate name (deprecated alias) | Canonical name |
|---|---|---|
| `KavachNestjsOptions` | `AuthNestjsOptions` | `TheAuthNestjsOptions` |
| `buildKavachRouter` | `buildAuthRouter` | `buildTheAuthRouter` |
| `kavachMiddleware` | `authMiddleware` | `theAuthMiddleware` |
| `KavachModuleOptions` | `AuthModuleOptions` | `TheAuthModuleOptions` |
| `KavachModule` | `AuthModule` | `TheAuthModule` |

### TanStack Start (`@glinr/theauth-tanstack`)

| Original name (removed) | Intermediate name (deprecated alias) | Canonical name |
|---|---|---|
| `KavachTanStackOptions` | `AuthTanStackOptions` | `TheAuthTanStackOptions` |
| `KavachTanStackHandlers` | `AuthTanStackHandlers` | `TheAuthTanStackHandlers` |
| `kavachTanStack` | `authTanStack` | `theAuthTanStack` |

### SvelteKit (`@glinr/theauth-sveltekit`)

| Original name (removed) | Intermediate name (deprecated alias) | Canonical name |
|---|---|---|
| `KavachSvelteKitOptions` | `AuthSvelteKitOptions` | `TheAuthSvelteKitOptions` |
| `KavachSvelteKitHandlers` | `AuthSvelteKitHandlers` | `TheAuthSvelteKitHandlers` |
| `kavachSvelteKit` | `authSvelteKit` | `theAuthSvelteKit` |

### Astro (`@glinr/theauth-astro`)

| Original name (removed) | Intermediate name (deprecated alias) | Canonical name |
|---|---|---|
| `KavachAstroOptions` | `AuthAstroOptions` | `TheAuthAstroOptions` |
| `KavachAstroHandlers` | `AuthAstroHandlers` | `TheAuthAstroHandlers` |
| `kavachAstro` | `authAstro` | `theAuthAstro` |

### Nuxt (`@glinr/theauth-nuxt`)

| Original name (removed) | Intermediate name (deprecated alias) | Canonical name |
|---|---|---|
| `KavachNuxtOptions` | `AuthNuxtOptions` | `TheAuthNuxtOptions` |
| `kavachNuxt` | `authNuxt` | `theAuthNuxt` |

### Fastify (`@glinr/theauth-fastify`)

| Original name (removed) | Intermediate name (deprecated alias) | Canonical name |
|---|---|---|
| `KavachFastifyOptions` | `AuthFastifyOptions` | `TheAuthFastifyOptions` |
| `kavachFastify` | `authFastify` | `theAuthFastify` |

### SolidStart (`@glinr/theauth-solidstart`)

| Original name (removed) | Intermediate name (deprecated alias) | Canonical name |
|---|---|---|
| `KavachSolidStartOptions` | `AuthSolidStartOptions` | `TheAuthSolidStartOptions` |
| `KavachSolidStartHandlers` | `AuthSolidStartHandlers` | `TheAuthSolidStartHandlers` |
| `kavachSolidStart` | `authSolidStart` | `theAuthSolidStart` |

### Prisma (`@glinr/theauth-prisma`)

| Original name (removed) | Intermediate name (deprecated alias) | Canonical name |
|---|---|---|
| `KavachPrismaAdapter` | `AuthPrismaAdapter` | `TheAuthPrismaAdapter` |

## Other things that changed with the removal

The `Kavach*` removal also renamed things that are not exports. Check each one before you upgrade a running deployment.

| Area | Before | Now |
|---|---|---|
| Database tables | `kavach_*` | `theauth_*`. `createTables` renames existing `kavach_*` tables in place and keeps their rows (see `packages/core/src/db/migrations.ts` and `packages/core/tests/legacy-table-rename.test.ts`). Back up first, as with any schema change. |
| Environment variables | `KAVACH_*` | `THEAUTH_*`. Variables you set yourself are not read under the old names. |
| Webhook headers | `X-Kavach-*` | `X-TheAuth-Delivery-Id`, `X-TheAuth-Event`, `X-TheAuth-Signature`, `X-TheAuth-Timestamp`. Update any receiver that reads or verifies them. |
| Cookie names and the default API route | `kavach` | `theauth`, per the release notes. If your own code reads a cookie by name or hard-codes the route, update it. |

Agent tokens still start with `kv_`. That prefix did not change.

## Migration guide

Replace every `Kavach*` identifier with its `TheAuth*` equivalent from the tables above. Find-and-replace or a codemod is enough, because no logic changed. `Auth*` names still work, but skip straight to `TheAuth*`.

```typescript
// Before
import { createKavach, KavachConfig } from "@glinr/theauth";
const auth = await createKavach(config);

// After
import { createTheAuth, TheAuthConfig } from "@glinr/theauth";
const auth = await createTheAuth(config);
```
