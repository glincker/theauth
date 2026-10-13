---
"@glinr/theauth-fastify": patch
"@glinr/theauth-nestjs": patch
"@glinr/theauth-nextjs": patch
"@glinr/theauth-astro": patch
"@glinr/theauth-nuxt": patch
"@glinr/theauth-sveltekit": patch
"@glinr/theauth-solidstart": patch
"@glinr/theauth-tanstack": patch
"@glinr/theauth-express": patch
"@glinr/theauth-hono": patch
---

Forward the `DPoP-Nonce` header on `/mcp/token` error responses so DPoP clients can complete the `use_dpop_nonce` retry, and allow the `DPoP` request header and expose `DPoP-Nonce` and `WWW-Authenticate` in the MCP CORS headers.
