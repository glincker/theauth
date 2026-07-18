# @glinr/theauth-dashboard

Admin UI for managing agents, permissions, and audit logs.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-dashboard)](https://www.npmjs.com/package/@glinr/theauth-dashboard)

## Install

```bash
npm install @glinr/@glinr/theauth-dashboard
```

Peer dependencies: React 19+

## Usage

### Embedded component

Mount the dashboard inside your existing React app:

```tsx
import { KavachDashboard } from "@glinr/theauth-dashboard";

export function AdminPage() {
  return (
    <KavachDashboard
      apiUrl="http://localhost:3000"
    />
  );
}
```

The component connects to your TheAuth API and renders the full admin interface, including agent management, permission inspection, and audit log queries.

### Standalone server

Run the dashboard without a React app using the CLI:

```bash
npx theauth dashboard
# Starts on http://localhost:3100

npx theauth dashboard --port 4000 --api http://localhost:3000
```

This starts a Hono server that serves the dashboard UI and proxies API requests to your TheAuth backend.

## Options

| Prop / Flag | Default | Description |
|---|---|---|
| `apiUrl` / `--api` | `http://localhost:3000` | URL of your TheAuth API |
| `--port` | `3100` | Port for the standalone server |

## Built with

- React 19
- TailwindCSS 4
- TanStack Query 5
- Lucide React

## Docs and support

- Documentation: [theauth.dev/docs](https://theauth.dev/docs)
- GitHub: [github.com/glincker/theauth](https://github.com/glincker/theauth)

## License

MIT
