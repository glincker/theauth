# @glinr/theauth-cli

[npm](https://www.npmjs.com/package/@glinr/theauth-cli) · [Source](https://github.com/glincker/theauth/tree/main/packages/cli) · [All packages](https://github.com/glincker/theauth#packages)

Setup wizard and dev tools for theAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-cli)](https://www.npmjs.com/package/@glinr/theauth-cli)

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Usage

No install required. Run with `npx`:

```bash
npx theauth <command>
```

## Commands

### `init`

Prints setup instructions for adding theAuth to a project, including install steps, configuration scaffold, and adapter options:

```bash
npx theauth init
```

### `migrate`

Runs database migrations (auto-applies schema on first run):

```bash
npx theauth migrate
```

### `dashboard`

Launches the standalone admin UI on port 3100 by default:

```bash
npx theauth dashboard

# Custom port and API URL
npx theauth dashboard --port 4000 --api http://localhost:3000
```

### `codemod rename`

Migrates `Kavach*` names, `KAVACH_*` env vars and old import paths to TheAuth. Dry run by default:

```bash
npx theauth codemod rename src
npx theauth codemod rename src --write --include-env
```

Reports `X-Kavach-*` headers, `kavach_*` table names and any other leftover mention without editing them. See the [migration guide](https://theauth.dev/docs/migrate/from-kavach).

## Options

| Flag | Default | Description |
|---|---|---|
| `--port` | `3100` | Port for the dashboard server |
| `--api` | `http://localhost:3000` | theAuth API URL |
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
