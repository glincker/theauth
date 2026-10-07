# @glinr/theauth-email

Email and password authentication plugin for TheAuth.

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
