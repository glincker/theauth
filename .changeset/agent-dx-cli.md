---
"@glinr/theauth-cli": minor
---

Make theAuth easy for AI coding assistants to install and use.

- New `theauth mcp` command: a stdio MCP server with read-only `search_docs`, `get_doc`, `add_plugin`, `generate_schema` and `inspect` tools. `inspect` never returns secret values.
- New `theauth init --agent` (with `--target`, `--dry-run`, `--force`): writes the theAuth skill and an MCP server entry for Claude Code, Cursor and VS Code, merging into existing config.
- The CLI build now bundles the skill and a docs search index into `dist/assets`.
