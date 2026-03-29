# Changelog

All notable changes to this project will be documented in this file.

## [0.0.6] - 2026-03-29

### Added
- Agent-to-Agent (A2A) protocol: `createAgentCard`, `validateAgentCard`, `signAgentCard`, `verifyAgentCard`
- Verifiable credentials module with `createCredential`, `verifyCredential`
- Decentralized identifiers (DID) support
- A2A JSON-RPC server and client

### Fixed
- Build exports for A2A subpath (`kavachos/a2a`)

## [0.0.5] - 2026-03-28

### Added
- 11 framework adapters: Hono, Express, Next.js, Fastify, Nuxt, SvelteKit, Astro, NestJS, SolidStart, TanStack Start, Prisma
- Client libraries: React, Vue, Svelte, Expo, Electron
- UI components: SignIn, SignUp, UserButton, OAuthButtons, ForgotPassword, TwoFactorVerify, AuthCard
- Test utilities: MockKavachProvider, factories, assertions
- Gateway: standalone auth proxy with rate limiting
- CLI: init, migrate, dashboard commands

### Changed
- Unified versioning across all @kavachos/* packages

## [0.0.4] - 2026-03-27

### Added
- MCP OAuth 2.1 authorization server (PKCE S256, RFC 9728/8707/8414/7591)
- OIDC Provider: auth code flow, PKCE, refresh token rotation, JWKS, discovery
- Organizations and RBAC
- SAML 2.0 + OIDC SSO
- SCIM directory sync
- Admin controls (ban, impersonate)
- Multi-tenant isolation

## [0.0.3] - 2026-03-26

### Added
- OAuth providers: Google, GitHub, Apple, Microsoft, Discord, Slack, GitLab, LinkedIn, Twitter/X, Facebook, Spotify, Twitch, Reddit, Notion
- Generic OIDC factory for custom providers
- Passkey/WebAuthn authentication
- TOTP two-factor authentication
- Magic link authentication
- Email OTP, phone SMS auth
- Google One-tap, SIWE
- Captcha support (reCAPTCHA, hCaptcha, Turnstile)

## [0.0.2] - 2026-03-25

### Added
- Permission engine with wildcard matching
- Delegation chains with depth limits and expiry
- Trust scoring and anomaly detection
- Budget policies and cost attribution
- CIBA-style approval flows
- Immutable audit trail with compliance export
- Session management (create, verify, revoke, refresh)
- Rate limiting (per-agent and per-IP)
- HIBP password breach checking
- GDPR compliance (export, delete, anonymize)

## [0.0.1] - 2026-03-24

### Added
- Initial release
- `createKavach` core initialization
- Agent identity: create, scope, revoke, rotate tokens
- Email + password authentication with bcrypt
- Database support: SQLite, PostgreSQL, MySQL, D1, libSQL
- Plugin architecture for auth methods
- Webhook delivery system
- Internationalization (i18n) support
