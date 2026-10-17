---
"@glinr/theauth": minor
"@glinr/theauth-cli": minor
"@glinr/theauth-mcp": minor
"@glinr/theauth-conformance": minor
"@glinr/theauth-agent-frameworks": minor
"@glinr/create-theauth-app": minor
"@glinr/theauth-gateway": minor
---

Add `theauth dev` (zero-config local first run), a Cloudflare Workers template, an opt-in `adminApi` plugin with an admin MCP server (read-only by default, writes gated by approval), a black-box agent-auth conformance suite, and LangGraph and Mastra approval wrappers.

Breaking behavior in the gateway: the client `Authorization` and `DPoP` headers are no longer forwarded to the upstream by default. Opt out with `--forward-auth` or `stripAuthHeader: false`. The gateway also gains an MCP mode, a 10 MiB request body limit, a 30 second upstream header timeout, and hop-by-hop and `X-Forwarded-*` header handling. Core gains a browser-safe `@glinr/theauth/browser` entry.
