# @glinr/create-theauth-app

[npm](https://www.npmjs.com/package/@glinr/create-theauth-app) · [Source](https://github.com/glincker/theauth/tree/main/packages/create-theauth-app) · [Docs](https://docs.theauth.dev/quickstart) · [All packages](https://github.com/glincker/theauth#packages)

Scaffold a theAuth app in one command.

```bash
npx @glinr/create-theauth-app my-agent-app --yes && cd my-agent-app && npm start
```

That writes the `first-run` template, runs the install, and starts a server where an agent is allowed one call and denied another, with both in the audit log. See [first run](https://github.com/glincker/theauth/blob/main/docs/first-run.md).

Without arguments it asks for a directory, a template and a package manager:

```bash
npm create @glinr/theauth-app
```

Options: `--template <first-run|next-saas|hono-mcp>`, `--yes` (use defaults, no prompts), `--no-install`, `--help`.

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Templates

| Template | Status | Stack |
| --- | --- | --- |
| `first-run` | available (default) | One agent, one allowed call, one denied call, audit log. In memory SQLite |
| `next-saas` | available | Next.js App Router · Drizzle · theAuth auth |
| `hono-mcp` | available | Hono server · MCP OAuth 2.1 |
| `expo-mobile` | coming soon | Expo Router · React Native |

## Database drivers

- `sql.js` (default): local SQLite compiled to WebAssembly, zero native build
- `pg`: Postgres (you provide the connection string)

## What you get with `next-saas`

A working Next.js app with:

- `createTheAuth` already wired in `lib/auth.ts`
- Drizzle schema and migrations for the auth tables
- Sign-in / sign-up routes using the prebuilt React components
- `.env.example` with the secrets you need to fill in

Then:

```bash
cd my-theauth-app
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
