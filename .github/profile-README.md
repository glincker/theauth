# GLINR STUDIOS

Owner: https://glincker.com

## TheAuth - Authentication and Authorization for AI Agents and Humans

TheAuth is an open-source authentication and authorization platform built for applications where AI agents and humans collaborate. It provides full human authentication (email, OAuth, passkeys, SSO) alongside agent-native primitives: API keys, delegation, capability-based permissions, and cryptographically verifiable audit trails.

## Core Features

**Authentication**

- Email and password with secure hashing
- OAuth 2.0 integrations (Google, GitHub, Microsoft)
- Passkeys and WebAuthn support
- Single Sign-On (SAML, OIDC)
- Device verification and 2FA

**Agent Authorization**

- Agent creation and lifecycle management
- Scoped delegation with real-time revocation
- Capability-based access control
- Time-limited credential grants
- Complete audit trail of all actions

**Developer Experience**

- Type-safe TypeScript SDKs
- Framework adapters: Next.js, Fastify, NestJS, Hono, Express
- Client libraries: React, Vue, Svelte, React Native
- Pre-built UI components and authentication flows
- Testing utilities and mocks

**Operations**

- Real-time audit logs
- Session tracking and analytics
- Compliance reporting (SOC 2, GDPR, HIPAA)
- Webhook events for authentication changes

## Quick Start

```bash
npm install @glinr/theauth
```

```typescript
import { createKavach } from "@glinr/theauth";
import { emailPassword } from "@glinr/theauth/auth";

const kavach = createKavach({
  database: { provider: "postgres", url: process.env.DATABASE_URL },
  plugins: [emailPassword()],
});
```

Use in React:

```tsx
import { useSession, useSignIn } from "@glinr/theauth-react";

export function App() {
  const { user } = useSession();
  const { signIn } = useSignIn();

  if (!user) {
    return <button onClick={() => signIn()}>Sign in</button>;
  }

  return <div>Signed in as {user.email}</div>;
}
```

Create an agent:

```typescript
const agent = await kavach.agents.create({
  userId: user.id,
  name: "assistant",
  capabilities: ["read:documents", "write:messages"],
  expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
});

const apiKey = agent.apiKey;
```

## Repository Structure

The TheAuth organization contains multiple repositories:

- **theauth** - Core monorepo with SDKs, adapters, and client libraries
- **theauth-cloud** - Managed service offering (deployment, API, dashboard)
- **docs** - Full documentation and guides

## Documentation

Learn more and get started at https://docs.theauth.com

See the main [theauth repository](https://github.com/glincker/theauth) for implementation details, API reference, and examples.

## Governance and Support

- [Governance Model](https://github.com/glincker/theauth/blob/main/GOVERNANCE.md)
- [Contributing Guidelines](https://github.com/glincker/theauth/blob/main/CONTRIBUTING.md)
- [Support Policy](https://github.com/glincker/theauth/blob/main/SUPPORT.md)
- [GitHub Discussions](https://github.com/glincker/theauth/discussions)

## Security

For security vulnerabilities, email support@glincker.com with reproduction steps and impact assessment. See [SECURITY.md](https://github.com/glincker/theauth/blob/main/SECURITY.md) for details.

## License

MIT
