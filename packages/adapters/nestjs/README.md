# @glinr/theauth-nestjs

NestJS adapter for TheAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-nestjs?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-nestjs)

## Install

```bash
npm install @glinr/theauth @glinr/theauth-nestjs
```

## Usage

### Module import

```typescript
import { Module } from "@nestjs/common";
import { TheAuthModule } from "@glinr/theauth-nestjs";

@Module({
  imports: [
    TheAuthModule.forRoot({
      database: { provider: "sqlite", url: "theauth.db" },
    }),
  ],
})
export class AppModule {}
```

### Middleware

```typescript
import { createTheAuth } from "@glinr/theauth";
import { theAuthMiddleware } from "@glinr/theauth-nestjs";

const theauth = createTheAuth({
  database: { provider: "postgres", url: process.env.DATABASE_URL },
});

// Apply as NestJS middleware
app.use("/api/theauth", theAuthMiddleware(theauth));
```

## Docs

[docs.theauth.dev/docs/adapters/nestjs](https://docs.theauth.dev/docs/adapters/nestjs)

## License

MIT
