# KavachOS - Authentication and Authorization for AI Agents and Humans

KavachOS is an open-source authentication and authorization platform built for applications where AI agents and humans collaborate. It provides full human authentication (email, OAuth, passkeys, SSO) alongside agent-native primitives: API keys, delegation, capability-based permissions, and cryptographically verifiable audit trails.

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
npm install kavachos
```

```typescript
import { createKavach } from "kavachos";
import { emailPassword } from "kavachos/auth";

const kavach = createKavach({
  database: { provider: "postgres", url: process.env.DATABASE_URL },
  plugins: [emailPassword()],
});
```

Use in React:

```tsx
import { useSession, useSignIn } from "@kavachos/react";

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

The KavachOS organization contains multiple repositories:

- **kavachos** - Core monorepo with SDKs, adapters, and client libraries
- **kavachos-cloud** - Managed service offering (deployment, API, dashboard)
- **docs** - Full documentation and guides

## Documentation

Learn more and get started at https://docs.kavachos.com

See the main [kavachos repository](https://github.com/kavachos/kavachos) for implementation details, API reference, and examples.

## Governance and Support

- [Governance Model](https://github.com/kavachos/kavachos/blob/main/GOVERNANCE.md)
- [Contributing Guidelines](https://github.com/kavachos/kavachos/blob/main/CONTRIBUTING.md)
- [Support Policy](https://github.com/kavachos/kavachos/blob/main/SUPPORT.md)
- [GitHub Discussions](https://github.com/kavachos/kavachos/discussions)

## Security

For security vulnerabilities, email security@kavachos.com with reproduction steps and impact assessment. See [SECURITY.md](https://github.com/kavachos/kavachos/blob/main/SECURITY.md) for details.

## License

MIT
