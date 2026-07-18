# @glinr/theauth-cli

Setup wizard and dev tools for TheAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-cli)](https://www.npmjs.com/package/@glinr/theauth-cli)

## Usage

No install required. Run with `npx`:

```bash
npx theauth <command>
```

## Commands

### `init`

Prints setup instructions for adding TheAuth to a project, including install steps, configuration scaffold, and adapter options:

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

## Options

| Flag | Default | Description |
|---|---|---|
| `--port` | `3100` | Port for the dashboard server |
| `--api` | `http://localhost:3000` | TheAuth API URL |
| `--help, -h` | | Show help |
| `--version` | | Show version |

## Docs and support

- Documentation: [theauth.dev/docs](https://theauth.dev/docs)
- GitHub: [github.com/glincker/theauth](https://github.com/glincker/theauth)

## License

MIT
