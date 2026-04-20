# create-kavachos-app

Scaffold a KavachOS app in one command.

```bash
npm create kavachos-app@latest
# or
pnpm create kavachos-app
# or
yarn create kavachos-app
# or
bunx create-kavachos-app
```

You'll be asked for a project directory, a template, and a database driver. The CLI then writes the project, installs deps, and prints the next commands to run.

## Templates

| Template | Status | Stack |
| --- | --- | --- |
| `next-saas` | available | Next.js App Router · Drizzle · KavachOS auth |
| `hono-mcp` | coming soon | Hono server · MCP OAuth 2.1 |
| `expo-mobile` | coming soon | Expo Router · React Native |

## Database drivers

- `better-sqlite3` (default): local SQLite, zero setup
- `pg`: Postgres (you provide the connection string)

## What you get

A working Next.js app with:

- `createKavach` already wired in `lib/auth.ts`
- Drizzle schema and migrations for the auth tables
- Sign-in / sign-up routes using the prebuilt React components
- `.env.example` with the secrets you need to fill in

## Next steps

```bash
cd my-kavachos-app
pnpm install
cp .env.example .env       # then set KAVACHOS_SECRET
pnpm db:push
pnpm dev
```

## Links

- KavachOS repo: <https://github.com/kavachos/kavachos>
- Docs: <https://docs.kavachos.com>

## License

MIT
