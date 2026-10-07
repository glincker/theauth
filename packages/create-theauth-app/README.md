# @glinr/create-theauth-app

[npm](https://www.npmjs.com/package/@glinr/create-theauth-app) · [Source](https://github.com/glincker/theauth/tree/main/packages/create-theauth-app) · [Docs](https://docs.theauth.dev/quickstart) · [All packages](https://github.com/glincker/theauth#packages)

Scaffold a theAuth app in one command.

```bash
npm create theauth-app@latest
# or
pnpm create theauth-app
# or
yarn create theauth-app
# or
bunx @glinr/create-theauth-app
```

You'll be asked for a project directory, a template, and a database driver. The CLI then writes the project, installs deps, and prints the next commands to run.

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Templates

| Template | Status | Stack |
| --- | --- | --- |
| `next-saas` | available | Next.js App Router · Drizzle · theAuth auth |
| `hono-mcp` | available | Hono server · MCP OAuth 2.1 |
| `expo-mobile` | coming soon | Expo Router · React Native |

## Database drivers

- `better-sqlite3` (default): local SQLite, zero setup
- `pg`: Postgres (you provide the connection string)

## What you get

A working Next.js app with:

- `createTheAuth` already wired in `lib/auth.ts`
- Drizzle schema and migrations for the auth tables
- Sign-in / sign-up routes using the prebuilt React components
- `.env.example` with the secrets you need to fill in

## Next steps

```bash
cd my-theauth-app
pnpm install
cp .env.example .env       # then set THEAUTH_SECRET
pnpm db:push
pnpm dev
```

## Links

- theAuth repo: <https://github.com/glincker/theauth>
- Docs: <https://docs.theauth.dev>

## Community

[![Discord](https://img.shields.io/discord/829168897080557579?style=flat-square&logo=discord&logoColor=white&label=discord&color=5865F2)](https://discord.gg/Ar5pcaZB99)

Questions and help in the `#theauth` forum on the [GLINR Discord](https://discord.gg/Ar5pcaZB99).

## License

MIT
