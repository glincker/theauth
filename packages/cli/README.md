# @glinr/theauth-cli

[npm](https://www.npmjs.com/package/@glinr/theauth-cli) · [Source](https://github.com/glincker/theauth/tree/main/packages/cli) · [All packages](https://github.com/glincker/theauth#packages)

Setup wizard and dev tools for theAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-cli)](https://www.npmjs.com/package/@glinr/theauth-cli)

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Usage

No install required. Run with `npx`:

```bash
npx @glinr/theauth-cli <command>
```

The binary is called `theauth`, so after `npm install -D @glinr/theauth-cli` you can run `npx theauth <command>` from that project. The bare `npx theauth` from an empty directory will work once the `theauth` alias package is published; until then use the scoped name above.

## First run

To see an agent allowed and denied in under a minute, scaffold the first-run project:

```bash
npx @glinr/create-theauth-app my-agent-app --yes && cd my-agent-app && npm start
```

## Commands

### `init`

Asks for a framework and database, then writes `theauth.config.ts` and `theauth.example.ts` and prints the install steps:

```bash
npx @glinr/theauth-cli init
```

### `migrate`

Runs database migrations (auto-applies schema on first run):

```bash
npx @glinr/theauth-cli migrate
```

### `dashboard`

Starts the admin dashboard on port 3100 with an in-memory database and sample data (three agents, one delegation, ten audit entries). It is a separate instance from your own server and does not read your data:

```bash
npx @glinr/theauth-cli dashboard
```

To serve the dashboard against an API you run yourself, use `--static`. The dashboard expects the unwrapped response shapes of the demo server, so this only works with an API that returns them:

```bash
npx @glinr/theauth-cli dashboard --static --port 4000 --api http://localhost:3000
```

### `codemod rename`

Migrates `Kavach*` names, `KAVACH_*` env vars and old import paths to TheAuth. Dry run by default:

```bash
npx @glinr/theauth-cli codemod rename src
npx @glinr/theauth-cli codemod rename src --write --include-env
```

Reports `X-Kavach-*` headers, `kavach_*` table names and any other leftover mention without editing them. See the [migration guide](https://theauth.dev/docs/migrate/from-kavach).

## Options

| Flag | Default | Description |
|---|---|---|
| `--port` | `3100` | Port for the dashboard server |
| `--static` | off | Serve only the dashboard files, no demo API |
| `--api` | `http://localhost:3000` | theAuth API URL (with `--static`) |
| `--help, -h` | | Show help |
| `--version` | | Show version |

## Docs and support

- Documentation: [docs.theauth.dev](https://docs.theauth.dev)
- GitHub: [github.com/glincker/theauth](https://github.com/glincker/theauth)

## Community

[![Discord](https://img.shields.io/discord/829168897080557579?style=flat-square&logo=discord&logoColor=white&label=discord&color=5865F2)](https://discord.gg/Ar5pcaZB99)

Questions and help in the `#theauth` forum on the [GLINR Discord](https://discord.gg/Ar5pcaZB99).

## License

MIT

## AI coding assistants

```bash
npx @glinr/theauth-cli init --agent     # skill + MCP config for Claude Code, Cursor, VS Code
npx @glinr/theauth-cli mcp              # stdio MCP server (docs search, add_plugin, generate_schema, inspect)
```

See https://docs.theauth.dev/ai-assistants.
