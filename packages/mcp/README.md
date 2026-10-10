<!-- mcp-name: io.github.glincker/theauth-mcp -->

# @glinr/theauth-mcp

Read-only MCP server for theAuth. Inspect agent identities, dry-run permission checks, query the audit log and decode tokens in a running theAuth deployment, straight from Claude, Cursor, VS Code or any MCP client. No tool changes state.

[npm](https://www.npmjs.com/package/@glinr/theauth-mcp) · [Source](https://github.com/glincker/theauth/tree/main/packages/mcp) · [theAuth](https://theauth.dev)

## Install

Requires Node 20 or newer and a running theAuth deployment that exposes the management routes (for example via `@glinr/theauth-hono`).

Claude Code:

```bash
claude mcp add theauth -e THEAUTH_API_URL=https://auth.example.com -e THEAUTH_API_KEY=your-key -- npx -y @glinr/theauth-mcp
```

Without the `-e` flags, export `THEAUTH_API_URL` and `THEAUTH_API_KEY` first:

```bash
claude mcp add theauth -- npx -y @glinr/theauth-mcp
```

Claude Desktop (`claude_desktop_config.json`) and Cursor (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "theauth": {
      "command": "npx",
      "args": ["-y", "@glinr/theauth-mcp"],
      "env": {
        "THEAUTH_API_URL": "https://auth.example.com",
        "THEAUTH_API_KEY": "your-key"
      }
    }
  }
}
```

VS Code (`.vscode/mcp.json`):

```json
{
  "servers": {
    "theauth": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@glinr/theauth-mcp"],
      "env": {
        "THEAUTH_API_URL": "https://auth.example.com",
        "THEAUTH_API_KEY": "${input:theauth-api-key}"
      }
    }
  },
  "inputs": [
    {
      "id": "theauth-api-key",
      "type": "promptString",
      "description": "theAuth API key",
      "password": true
    }
  ]
}
```

## Tools

| Tool | Description | Inputs |
| --- | --- | --- |
| `check_permission` | Dry-run whether an agent may do an action on a resource. Returns the decision and a trace. Writes nothing. | `agentId`, `action`, `resource`, optional `arguments`, `ip`, `timestamp` |
| `list_agents` | List agent identities with owner, type, status, expiry and permissions. | optional `status`, `type`, `ownerId`, `limit` (default 50, max 200) |
| `get_agent` | Fetch one agent by id. Never returns its token. | `agentId` |
| `query_audit` | Query the audit log. Secret-looking fields are redacted. | optional `agentId`, `userId`, `since`, `until`, `result`, `actions`, `limit` (default 50, max 500), `offset` |
| `inspect_token` | Decode a JWT or recognise an agent token and report algorithm, issuer, audience, scopes and expiry state. Local only, signature is not verified, the token is never echoed. | `token` |
| `doctor` | Sanity-check the deployment: transport, key accepted, audit queryable, MCP OAuth metadata, simulator plugin. | none |

`check_permission` calls `POST /agents/:id/simulate`, which comes from the opt-in `simulator` plugin and needs a key that passes its `isAdmin` check. The other API-backed tools use `GET /agents`, `GET /agents/:id` and `GET /audit`. `doctor` reports which of these your deployment actually serves.

## Environment variables

| Variable | Required | Description |
| --- | --- | --- |
| `THEAUTH_API_URL` | yes | Base URL of the theAuth HTTP API, including any mount prefix. |
| `THEAUTH_API_KEY` | yes | Secret. Sent as `Authorization: Bearer <key>`. Must be accepted by your adapter's `authenticate` resolver (or be a valid session token). Never logged. |
| `THEAUTH_TIMEOUT_MS` | no | Per-request timeout in milliseconds. Default `10000`. |

## Security

- Every tool is annotated read-only. There are no create, rotate, revoke or delegate tools.
- Logs go to stderr only. stdout is the protocol channel.
- Use a dedicated, least-privilege key. Anything the key can read, the model can read.
- Container image: from the repository root run `docker build -f packages/mcp/Dockerfile -t theauth-mcp .`, then pass the variables at run time with `-e`. Nothing secret is baked in.

## License

MIT
