---
title: Database Setup
description: Configure TheAuth with SQLite, Postgres, MySQL, or Cloudflare D1. Covers connection setup, migration, WAL mode for SQLite, and skipping auto-migrations.
---

# Database Setup

TheAuth uses [Drizzle ORM](https://orm.drizzle.team) under the hood. You pick a provider and pass the connection URL; TheAuth handles the rest.

## Choosing a provider

| Provider | Best for |
|---|---|
| SQLite | Local dev, single-server deploys, serverless edge (with Turso) |
| Postgres | Production, high-concurrency, multi-tenant |
| MySQL | Existing MySQL infrastructure |
| Cloudflare D1 | Workers deployments, edge-native |

## Setup

=== "SQLite"
    SQLite is the default for development. No peer dependencies beyond `better-sqlite3`, which ships with `@glinr/theauth`.

    ```typescript
    import { createTheAuth } from '@glinr/theauth';

    const kavach = await createTheAuth({
      database: {
        provider: 'sqlite',
        url: './kavach.db',
      },
    });
    ```

    For in-memory SQLite (tests and CI), use `:memory:` as the URL:

    ```typescript
    const kavach = await createTheAuth({
      database: {
        provider: 'sqlite',
        url: ':memory:',
      },
    });
    ```

    TheAuth enables WAL mode and foreign keys automatically:
    ```sql
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    ```
=== "Postgres"
    Install the `pg` peer dependency:

    ```bash
    pnpm add pg
    pnpm add -D @types/pg
    ```

    ```typescript
    import { createTheAuth } from '@glinr/theauth';

    const kavach = await createTheAuth({
      database: {
        provider: 'postgres',
        url: process.env.DATABASE_URL!, // postgresql://user:pass@host:5432/db
      },
    });
    ```
=== "MySQL"
    Install the `mysql2` peer dependency:

    ```bash
    pnpm add mysql2
    ```

    ```typescript
    import { createTheAuth } from '@glinr/theauth';

    const kavach = await createTheAuth({
      database: {
        provider: 'mysql',
        url: process.env.DATABASE_URL!, // mysql://user:pass@host:3306/db
      },
    });
    ```
=== "Cloudflare D1"
    No peer dependency. Pass the `D1Database` binding from your Worker environment.

    ```typescript
    import { createTheAuth } from '@glinr/theauth';

    type Env = { KAVACH_DB: D1Database };

    export default {
      async fetch(request: Request, env: Env) {
        const kavach = await createTheAuth({
          database: {
            provider: 'd1',
            binding: env.KAVACH_DB,
          },
        });
        // ...
      },
    };
    ```

    Bind a D1 database in `wrangler.toml`:

    ```toml
    [[d1_databases]]
    binding = "KAVACH_DB"
    database_name = "kavach"
    database_id = "<your-database-id>"
    ```

## Auto-migrations

By default, TheAuth runs `CREATE TABLE IF NOT EXISTS` for all its tables on first boot. This is safe to run on every startup.

To skip auto-migrations (for example, when managing migrations with Flyway or drizzle-kit):

```typescript
const kavach = await createTheAuth({
  database: {
    provider: 'postgres',
    url: process.env.DATABASE_URL!,
    skipMigrations: true,
  },
});
```

## Prisma

A Prisma-compatible adapter is available:

```bash
pnpm add @glinr/theauth-prisma
```

```typescript
import { PrismaClient } from '@prisma/client';
import { createTheAuth } from '@glinr/theauth';
import { prismaAdapter } from '@glinr/theauth-prisma';

const prisma = new PrismaClient();

const kavach = await createTheAuth({
  database: prismaAdapter(prisma),
});
```

## Connection config reference

| Option | Type | Description |
|---|---|---|
| `provider` | `"sqlite" \| "postgres" \| "mysql" \| "d1"` | Database driver. Required. |
| `url` | `string` | File path for SQLite, connection string for Postgres/MySQL. Not used with D1. |
| `binding` | `D1Database` | D1Database binding from the Worker environment. Required when provider is `"d1"`. |
| `skipMigrations` | `boolean` | Skip auto-migrations on init. Defaults to `false`. |

## Related pages

- [Configuration](../reference/configuration.md)
- [Getting Started: Choosing an Adapter](../getting-started/choosing-an-adapter.md)
