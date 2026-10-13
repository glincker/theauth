---
"@glinr/theauth": patch
"@glinr/theauth-hono": minor
"@glinr/theauth-nextjs": minor
"@glinr/theauth-nuxt": minor
"@glinr/theauth-sveltekit": minor
"@glinr/theauth-astro": minor
"@glinr/theauth-solidstart": minor
"@glinr/theauth-tanstack": minor
---

The remaining adapters now apply the same rate limits and cross-site write check as Express, Fastify and NestJS (`rateLimit`, `trustedOrigins`, `csrf`). The strict tier also matches when the adapter is mounted under a path prefix.
