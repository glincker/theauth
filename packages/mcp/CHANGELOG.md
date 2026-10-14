# @glinr/theauth-mcp

## 1.1.1

### Patch Changes

- First release on the 1.x line. The public API is the one documented in [STABILITY.md](https://github.com/glincker/theauth/blob/main/STABILITY.md) and there are no API changes from the previous 0.x release. From here breaking changes only ship in a major.

## 0.2.0

### Minor Changes

- c79f439: Add `@glinr/theauth-mcp`, a read-only stdio MCP server for inspecting a theAuth deployment from any MCP client. Tools: `check_permission` (simulator dry run), `list_agents`, `get_agent`, `query_audit`, `inspect_token` (local decode, signature not verified) and `doctor`. Configured with `THEAUTH_API_URL` and `THEAUTH_API_KEY`.
