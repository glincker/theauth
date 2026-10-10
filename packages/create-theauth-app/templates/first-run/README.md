# __APP_NAME__

A small server that shows what theAuth does for an AI agent: it gets its own
token, one request is allowed, another is denied, and both are in the audit log.

```bash
npm install
npm start
```

The server prints the agent token and three curl commands. Run the first two,
then the third:

```bash
curl http://localhost:3000/mcp/github/repos -H "Authorization: Bearer <token>"
curl -X DELETE http://localhost:3000/mcp/github/repos -H "Authorization: Bearer <token>"
curl http://localhost:3000/audit
```

The first returns `allowed: true`, the second returns 403 with the reason, and
`/audit` lists both entries.

## Where to look

`src/server.ts` is the whole app, one short file. The permission is declared
where the agent is created: `{ resource: "mcp:github:*", actions: ["read"] }`.
`authorizeByToken` is the check, and it writes the audit row.

## Dashboard

```bash
npx @glinr/theauth-cli dashboard
```

This starts the admin dashboard with its own in-memory sample data. It does not
read this server's database yet, so use `/audit` here for your own entries.

## Next

- The database is in memory. For a file or Postgres, change `database` in
  `src/server.ts` (see https://docs.theauth.dev/quickstart).
- The `/audit` route has no authentication. Put the adapter's `authenticate`
  option in front of the management routes before you expose anything
  (`npm install @glinr/theauth-hono`).
- Short `npx theauth` commands work once the alias package is published. Until
  then use `npx @glinr/theauth-cli`.
