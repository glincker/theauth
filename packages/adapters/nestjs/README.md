# @kavachos/nestjs

NestJS adapter for KavachOS.

[![npm](https://img.shields.io/npm/v/@kavachos/nestjs?style=flat-square)](https://www.npmjs.com/package/@kavachos/nestjs)

## Install

```bash
npm install kavachos @kavachos/nestjs
```

## Usage

### Module import

```typescript
import { Module } from "@nestjs/common";
import { KavachModule } from "@kavachos/nestjs";

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
import { createKavach } from "kavachos";
import { kavachMiddleware } from "@kavachos/nestjs";

const kavach = createKavach({
  database: { provider: "postgres", url: process.env.DATABASE_URL },
});

// Apply as NestJS middleware
app.use("/api/kavach", kavachMiddleware(kavach));
```

## Docs

[docs.kavachos.com/docs/adapters/nestjs](https://docs.kavachos.com/docs/adapters/nestjs)

## License

MIT
