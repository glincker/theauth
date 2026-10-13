---
"@glinr/theauth": minor
"@glinr/theauth-express": minor
"@glinr/theauth-fastify": minor
"@glinr/theauth-nestjs": minor
---

Express, Fastify and NestJS adapters now rate limit requests in three tiers and reject cross-site writes made with a cookie session. New options on every adapter: `rateLimit`, `trustedOrigins` and `csrf`. Both checks are on by default; set `rateLimit: false` or `csrf: false` to opt out.
