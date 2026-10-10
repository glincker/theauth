# First run

This page gets you from an empty directory to a running server where an AI agent has its own token, one permission check is allowed, another is denied, and the audit log shows both. It needs Node 20 or newer and takes about a minute.

## The command

```bash
npx @glinr/create-theauth-app my-agent-app --yes && cd my-agent-app && npm start
```

The scaffolder writes the project, runs `npm install`, and the last step starts the server. Pass `--no-install` if you would rather run the install yourself. The short `npx theauth` form does not work yet: the `theauth` alias package exists in this repo but is not on npm, so use the scoped names above and below.

## Five line quickstart

```bash
npx @glinr/create-theauth-app my-agent-app --yes && cd my-agent-app && npm start
# the server prints an agent token and three curl commands
curl http://localhost:3000/mcp/github/repos -H "Authorization: Bearer <token>"            # allowed
curl -X DELETE http://localhost:3000/mcp/github/repos -H "Authorization: Bearer <token>"  # denied, 403
curl http://localhost:3000/audit                                                          # both are logged
```

## What you get

A project with one source file, `src/server.ts`, and no secrets. The database is in memory SQLite, so stopping the server resets everything. `.env.example` only documents `PORT`.

The agent is created with one permission:

```typescript
const agent = await auth.agent.create({
  ownerId: "owner-1",
  name: "github-reader",
  type: "autonomous",
  permissions: [{ resource: "mcp:github:*", actions: ["read"] }],
});
```

The endpoint `/mcp/github/repos` calls `authorizeByToken` with the bearer token. A `GET` asks for the `read` action and passes. A `DELETE` asks for `delete`, which no permission grants, so it returns 403 with the reason. Each check writes an audit row, and `/audit` lists them.

## The dashboard

```bash
npx @glinr/theauth-cli dashboard
```

This opens the admin dashboard on port 3100 with its own in memory database and sample data. It does not read the server you just scaffolded, so use `/audit` for your own entries. Pointing the dashboard at your own API is not supported yet, because it expects different response shapes than the adapters return.

## Other options

- `npx @glinr/create-theauth-app` with no arguments asks for a directory, a template and a package manager. `first-run` is the default template, `next-saas` and `hono-mcp` are the larger ones.
- `npx @glinr/theauth-cli init` writes `theauth.config.ts` and `theauth.example.ts` into an existing project.
- `npx @glinr/theauth-cli doctor` checks a project for common setup mistakes.

## Before you go further

The `/audit` route in the generated server has no authentication and the server binds to `127.0.0.1` for that reason. Before you expose anything, mount the management routes through an adapter such as `@glinr/theauth-hono` and pass its `authenticate` option. Note that `createTheAuth` only creates the agent and audit tables when the `agents` config key is present, which is why the generated server sets `agents: { enabled: true }`.
