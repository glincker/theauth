---
"@glinr/create-theauth-app": minor
"@glinr/theauth": minor
"@glinr/theauth-astro": minor
"@glinr/theauth-cli": minor
"@glinr/theauth-client": minor
"@glinr/theauth-dashboard": minor
"@glinr/theauth-electron": minor
"@glinr/theauth-email": minor
"@glinr/theauth-expo": minor
"@glinr/theauth-express": minor
"@glinr/theauth-fastify": minor
"@glinr/theauth-gateway": minor
"@glinr/theauth-hono": minor
"@glinr/theauth-nestjs": minor
"@glinr/theauth-nextjs": minor
"@glinr/theauth-nextjs-auth": minor
"@glinr/theauth-nuxt": minor
"@glinr/theauth-plugin-discovery": minor
"@glinr/theauth-plugin-telemetry": minor
"@glinr/theauth-prisma": minor
"@glinr/theauth-react": minor
"@glinr/theauth-solidstart": minor
"@glinr/theauth-svelte": minor
"@glinr/theauth-sveltekit": minor
"@glinr/theauth-tanstack": minor
"@glinr/theauth-test-utils": minor
"@glinr/theauth-ui": minor
"@glinr/theauth-ui-headless": minor
"@glinr/theauth-vue": minor
---

Remove the legacy KavachOS naming. The deprecated `Kavach*` and `createKavach` exports are gone: use `TheAuth*` and `createTheAuth`. Environment variables are now `THEAUTH_*`, webhook headers `X-TheAuth-*`, cookies and the default API route use `theauth`, and database tables are `theauth_*` (existing `kavach_*` tables are renamed in place by `createTables`, no data is lost). `Auth*` aliases remain deprecated.
