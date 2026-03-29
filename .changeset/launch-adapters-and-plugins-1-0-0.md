---
"@kavachos/astro": major
"@kavachos/auth-email": major
"@kavachos/express": major
"@kavachos/fastify": major
"@kavachos/gateway": major
"@kavachos/hono": major
"@kavachos/nestjs": major
"@kavachos/nextjs": major
"@kavachos/nuxt": major
"@kavachos/plugin-discovery": major
"@kavachos/plugin-telemetry": major
"@kavachos/prisma": major
"@kavachos/solidstart": major
"@kavachos/sveltekit": major
"@kavachos/tanstack": major
---

Launch wave B: explicit major alignment for adapters/plugins after core moves to the 0.1 line.

Why major:

- These packages are pre-1.0 and depend on core package version semantics.
- Core 0.0.x -> 0.1.x is treated as breaking for dependent package versioning.

Operator notes:

- Publish this wave separately from the core/client 0.1.0 wave.
- Keep `@kavachos/dashboard` on its independent track.
