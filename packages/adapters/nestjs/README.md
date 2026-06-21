# @glinr/theauth-nestjs

NestJS adapter for TheAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-nestjs?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-nestjs)

## Install

```bash
npm install theauth @glinr/@glinr/theauth-nestjs
```

## Usage

### Module import

```typescript
import { Module } from "@nestjs/common";
import { KavachModule } from "@glinr/theauth-nestjs";

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
import { createKavach } from "@glinr/theauth";
import { kavachMiddleware } from "@glinr/theauth-nestjs";

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
