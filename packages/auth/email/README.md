# @glinr/theauth-email

[npm](https://www.npmjs.com/package/@glinr/theauth-email) · [Source](https://github.com/glincker/theauth/tree/main/packages/auth/email) · [Docs](https://docs.theauth.dev/auth/email-password) · [All packages](https://github.com/glincker/theauth#packages)

Email and password authentication plugin for theAuth.

> **Deprecated.** Core now has email and password built in (the `emailPassword` config key and the `/auth/email/*` routes, see the [docs](https://docs.theauth.dev/auth/email-password)). This plugin's sign-in token is not a core session: `GET /auth/session` answers 401 for it, it sets no cookie, and its sign-up returns a session token before the address is verified. Use it only to keep an existing install running.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-email?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-email)

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Install

```bash
npm install @glinr/theauth-email
```

## Usage

```typescript
import { createEmailAuth, emailPassword } from "@glinr/theauth-email";
import { theauth } from "@glinr/theauth";

const emailAuthModule = await createEmailAuth({
  db: theauth.db,
  // Optional: configure password policies
});

// Add as a plugin to your auth config
```

## Exports

- `createEmailAuth`: initialize email authentication
- `emailPassword`: plugin for password-based auth
- `hashPassword`, `verifyPassword`: password utilities
- `validatePasswordStrength`: check password complexity

## Docs

[https://go.theauth.dev](https://go.theauth.dev)

## License

MIT

<!-- theauth:links -->
## Learn more

- [Email and password](https://docs.theauth.dev/auth/email-password)
- [Quickstart](https://docs.theauth.dev/quickstart)
- [All packages](https://github.com/glincker/theauth#packages)
- [GitHub Discussions](https://github.com/glincker/theauth/discussions) for questions
- [Report a security issue](https://github.com/glincker/theauth/blob/main/SECURITY.md)
