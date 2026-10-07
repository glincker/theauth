---
"@glinr/theauth": patch
"@glinr/theauth-hono": patch
"@glinr/theauth-express": patch
"@glinr/theauth-fastify": patch
"@glinr/theauth-nextjs": patch
"@glinr/theauth-nestjs": patch
"@glinr/theauth-astro": patch
"@glinr/theauth-sveltekit": patch
"@glinr/theauth-nuxt": patch
"@glinr/theauth-solidstart": patch
"@glinr/theauth-tanstack": patch
---

Delegation requests whose permissions are not a subset of the parent's now return HTTP 400 with error code `DELEGATION_PERMISSION_SUBSET` instead of a 500. Core throws a typed `DelegationError` (codes `DELEGATION_PERMISSION_SUBSET` and `DELEGATION_DEPTH_EXCEEDED`) and every REST adapter maps it to a 400 using that code.
