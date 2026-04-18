# Template 01, Tool allowlist

An agent must only call tools that are explicitly listed. Any unlisted tool call is refused. This is the simplest hardening step for production agents: do not rely on the agent's own judgment to stay in scope.

## Input shape

```ts
engine.evaluate({
  subject: { agentId: "agent-xyz" },
  action: "execute",
  resource: "tool:<name>",
});
```

## Example decisions

| Resource | Action | Decision |
|---|---|---|
| `tool:web_search` | `execute` | **allow**, listed |
| `tool:file_read` | `execute` | **allow**, listed |
| `tool:shell_exec` | `execute` | **deny**, not listed |

## Tweak this

- Replace `"execute"` with `["execute", "read"]` if a tool supports multiple modes.
- Add `constraints: { maxCallsPerHour: 50 }` to any entry to pair allowlisting with a rate cap (see template 04).
