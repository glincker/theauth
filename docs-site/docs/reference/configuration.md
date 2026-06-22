---
title: Configuration
description: Reference for every createKavach() option in KavachConfig. Covers database providers, agent settings, MCP OAuth, session config, and anomaly detection.
---

# Configuration

`createKavach()` accepts a `KavachConfig` object. The only required field is `database`. Everything else is optional and enables features incrementally.

```typescript
import { createKavach } from '@glinr/theauth';

const kavach = await createKavach({
  database: { provider: 'sqlite', url: 'kavach.db' },
});
```

## Common development setup

A minimal config for local development with email/password auth and no email sending:

```typescript
import { createKavach } from '@glinr/theauth';
import { emailPassword } from '@glinr/theauth/auth';

const kavach = await createKavach({
  database: { provider: 'sqlite', url: './kavach.db' },
  plugins: [
    emailPassword({
      requireVerification: false, // skip in dev
      onSendVerification: async (email, token) => {
        console.log(`Verify: http://localhost:3000/verify?token=${token}`);
      },
    }),
  ],
});
```

## Top-level options

| Option | Type | Description |
|---|---|---|
| `database` | `DatabaseConfig` | Database connection config. Required. |
| `agents` | `AgentConfig` | Agent identity settings. |
| `mcp` | `McpConfig` | MCP OAuth 2.1 authorization server. |
| `auth` | `{ adapter?, session? }` | Human auth adapter and session config. |
| `anomaly` | `AnomalyConfig` | Anomaly detection thresholds. |
| `approval` | `ApprovalConfig` | CIBA async approval flow config. |
| `trust` | `TrustConfig` | Graduated autonomy trust scoring. |
| `telemetry` | `TelemetryConfig` | OpenTelemetry integration via hooks. |
| `hooks` | `KavachHooks` | Lifecycle hooks for sandboxing and custom validation. |
| `baseUrl` | `string` | Base URL for the auth server (e.g. `https://auth.example.com`). |
| `secret` | `string` | Secret key used to sign tokens. Min 32 characters. |
| `emitAgenticJwtClaims` | `boolean` | Emit IETF draft agentic JWT claims on issued tokens. |

## Database config

| Option | Type | Description |
|---|---|---|
| `provider` | `"sqlite" \| "postgres" \| "mysql" \| "d1"` | Database driver. Required. |
| `url` | `string` | File path for SQLite, connection string for Postgres/MySQL. Not used with D1. |
| `binding` | `D1Database` | D1Database binding from the Worker environment. Required when provider is `"d1"`. |
| `skipMigrations` | `boolean` | Skip automatic `CREATE TABLE IF NOT EXISTS` on init. Defaults to `false`. |

```typescript
// Cloudflare D1 (edge)
database: { provider: 'd1', binding: env.KAVACH_DB }

// SQLite (Node.js)
database: { provider: 'sqlite', url: './kavach.db' }

// PostgreSQL
database: { provider: 'postgres', url: process.env.DATABASE_URL }

// MySQL
database: { provider: 'mysql', url: process.env.DATABASE_URL }

// In-memory SQLite (tests)
database: { provider: 'sqlite', url: ':memory:' }
```

## Agent config

| Option | Type | Description |
|---|---|---|
| `enabled` | `boolean` | Enable agent identity management. |
| `maxPerUser` | `number` | Maximum number of agents a single user can create. |
| `defaultPermissions` | `string[]` | Permission strings assigned to every new agent unless overridden. |
| `auditAll` | `boolean` | Write every agent action to the audit log regardless of permission outcome. |
| `tokenExpiry` | `string` | Default token expiry duration string (e.g. `"7d"`, `"24h"`, `"30m"`). |

```typescript
agents: {
  enabled: true,
  maxPerUser: 10,
  defaultPermissions: [],
  auditAll: true,
  tokenExpiry: '30d',
},
```

## MCP config

| Option | Type | Description |
|---|---|---|
| `enabled` | `boolean` | Enable the MCP authorization server. |
| `issuer` | `string` | Token issuer URL. Appears as the `iss` claim in JWTs. |
| `baseUrl` | `string` | Base path for MCP endpoints. |
| `signingSecret` | `string` | Secret used to sign JWTs. Min 32 characters. Defaults to the top-level `secret`. |
| `accessTokenTtl` | `number` | Access token lifetime in seconds. Defaults to 3600. |
| `refreshTokenTtl` | `number` | Refresh token lifetime in seconds. Defaults to 604800. |
| `codeTtl` | `number` | Authorization code lifetime in seconds. Defaults to 600. |
| `enforceAuth` | `boolean` | Reject all MCP requests without a valid Bearer token. |
| `scopes` | `string[]` | Custom OAuth scopes supported by this server. |
| `allowedResources` | `string[]` | Allowed resource URIs for RFC 8707 resource indicators. |
| `loginPage` | `string` | URL of your login page. Users are redirected here when unauthenticated. |
| `consentPage` | `string` | URL of your consent page. Users are redirected here to approve scopes. |
| `preRegisteredClients` | `Array<...>` | OAuth clients registered at startup. |
| `getAdditionalClaims` | `function` | Async function to add custom claims to issued tokens. |

```typescript
mcp: {
  enabled: true,
  issuer: 'https://auth.example.com',
  baseUrl: 'https://auth.example.com',
  accessTokenTtl: 3600,
  refreshTokenTtl: 604800,
  enforceAuth: true,
  loginPage: 'https://example.com/login',
  consentPage: 'https://example.com/consent',
},
```

## Auth config

Connects TheAuth to your existing auth provider so it can resolve the human user behind incoming requests.

```typescript
auth: {
  adapter: betterAuthAdapter(auth),   // resolves user from request
  session: {                          // optional: TheAuth-managed sessions
    secret: process.env.SESSION_SECRET,
    maxAge: 60 * 60 * 24 * 30,       // 30 days in seconds
  },
},
```

When `auth` is omitted, `kavach.auth.resolveUser()` always returns `null` (manual user management mode).

## Session config

| Option | Type | Default | Description |
|---|---|---|---|
| `secret` | `string` | required | Signing secret for session JWTs. Min 32 characters. |
| `maxAge` | `number` | `604800` (7 days) | Session lifetime in seconds. |
| `cookieName` | `string` | `'kavach_session'` | Name of the session cookie. |
| `freshAge` | `number` | `300` (5 minutes) | Maximum session age in seconds to be considered fresh. |

## Password reset config

| Option | Type | Default | Description |
|---|---|---|---|
| `sendResetEmail` | `function` | required | Callback to deliver the reset email. Receives email, raw token, and constructed URL. |
| `resetUrl` | `string` | required | Base URL for the reset page. Token is appended as `?token=...` |
| `tokenTtlSeconds` | `number` | `3600` (1h) | Reset token lifetime in seconds. |
| `revokeSessionsOnReset` | `boolean` | `true` | Revoke all sessions when the password is successfully reset. |
| `minPasswordLength` | `number` | `8` | Minimum new password length. |
| `maxPasswordLength` | `number` | `128` | Maximum new password length. |

!!! warning
    Always use an HTTPS URL for `resetUrl` in production. Reset tokens in plain HTTP links can be intercepted in transit or leaked via `Referer` headers.

## Plugins

TheAuth features are composable. Enable what you need:

| Plugin | Import | What it does |
|---|---|---|
| `emailPassword` | `@glinr/theauth/auth` | Email and password with verification and reset |
| `passkey` | `@glinr/theauth/auth` | WebAuthn/FIDO2 biometric auth |
| `magicLink` | `@glinr/theauth/auth` | Passwordless email links |
| `emailOtp` | `@glinr/theauth/auth` | One-time password codes via email |
| `twoFactor` | `@glinr/theauth/auth` | TOTP 2FA with backup codes |
| `multiSession` | `@glinr/theauth/auth` | Session limits and device management |
| `organization` | `@glinr/theauth/auth` | Organizations with RBAC |
| `apiKeys` | `@glinr/theauth/auth` | Static API key management |
| `admin` | `@glinr/theauth/auth` | User management, banning, impersonation |
| `stripe` | `@glinr/theauth/auth` | Stripe billing integration |
| `polar` | `@glinr/theauth/auth` | Polar payment integration |
| `gdpr` | `@glinr/theauth/auth` | GDPR data export and deletion |

## Anomaly config

| Option | Type | Description |
|---|---|---|
| `highFrequencyThreshold` | `number` | Calls per agent per hour before flagging as high-frequency. Defaults to 500. |
| `highDenialRateThreshold` | `number` | Denial rate percentage that triggers an alert. Defaults to 50. |
| `expectedHours` | `{ start: number; end: number }` | Flag access outside these hours (0-23) as off-hours anomaly. Optional. |

```typescript
anomaly: {
  highFrequencyThreshold: 200,
  highDenialRateThreshold: 30,
  expectedHours: { start: 8, end: 20 },
},
```

## Environment variables pattern

Never hardcode secrets in config. Pass them through environment variables:

```typescript
const kavach = await createKavach({
  database: {
    provider: 'postgres',
    url: process.env.DATABASE_URL!,
  },
  secret: process.env.KAVACH_SECRET!,
  mcp: {
    enabled: true,
    issuer: process.env.KAVACH_ISSUER!,
    signingSecret: process.env.KAVACH_SIGNING_SECRET,
  },
});
```

## Dev vs production example

```typescript
// config/kavach.ts
const isDev = process.env.NODE_ENV !== 'production';

export const kavach = await createKavach({
  database: isDev
    ? { provider: 'sqlite', url: './kavach-dev.db' }
    : { provider: 'postgres', url: process.env.DATABASE_URL! },

  secret: process.env.KAVACH_SECRET!,
  baseUrl: process.env.KAVACH_BASE_URL ?? 'http://localhost:3000',

  agents: {
    enabled: true,
    maxPerUser: isDev ? 100 : 25,
    auditAll: true,
    tokenExpiry: '30d',
  },

  mcp: {
    enabled: true,
    issuer: process.env.KAVACH_BASE_URL ?? 'http://localhost:3000',
    accessTokenTtl: isDev ? 86400 : 3600,
    enforceAuth: !isDev,
    loginPage: '/login',
    consentPage: '/consent',
  },

  anomaly: {
    highFrequencyThreshold: 500,
    highDenialRateThreshold: 50,
  },
});
```

!!! warning
    `secret` and `mcp.signingSecret` must be at least 32 characters. In production, generate them with `openssl rand -base64 32`.
