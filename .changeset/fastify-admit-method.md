---
"@glinr/theauth-fastify": patch
"@glinr/theauth-express": patch
"@glinr/theauth-nestjs": patch
---

Fastify now passes the real request method to the rate limit and cross-site checks (it was always GET, so writes were counted as reads and the cross-site check never ran). Express and NestJS skip re-encoding the parsed body for those checks.
