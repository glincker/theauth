# @theauth/nestjs

NestJS adapter for TheAuth.

[![npm](https://img.shields.io/npm/v/@theauth/nestjs?style=flat-square)](https://www.npmjs.com/package/@theauth/nestjs)

## Install

```bash
npm install theauth @theauth/nestjs
```

## Usage

### Module import

```typescript
import { Module } from "@nestjs/common";
import { KavachModule } from "@theauth/nestjs";

@Module({
  imports: [
    KavachModule.forRoot({
      database: { provider: "sqlite", url: "kavach.db" },
    }),
  ],
})
export class AppModule {}
```

### Middleware

```typescript
import { createKavach } from "theauth";
import { kavachMiddleware } from "@theauth/nestjs";

const kavach = createKavach({
  database: { provider: "postgres", url: process.env.DATABASE_URL },
});

// Apply as NestJS middleware
app.use("/api/kavach", kavachMiddleware(kavach));
```

## Docs

[docs.theauth.com/docs/adapters/nestjs](https://docs.theauth.com/docs/adapters/nestjs)

## License

MIT
