---
"@glinr/theauth-gateway": patch
---

The gateway CLI now enables agents when it creates its TheAuth instance, so a fresh database gets the agent, audit and related tables at startup and the first agent call no longer fails with "no such table". The legacy table rename step in core is unchanged.
