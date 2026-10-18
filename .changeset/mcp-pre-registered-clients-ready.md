---
"@glinr/theauth": patch
---

A request that arrives while the MCP module is still writing its `preRegisteredClients` now waits for them instead of answering `invalid_client` for a client that is configured. A failed pre-registration write is thrown to the first client lookup, not lost.
