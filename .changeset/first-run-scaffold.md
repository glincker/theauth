---
"@glinr/create-theauth-app": minor
"@glinr/theauth-cli": minor
---

Add a `first-run` template to the app scaffolder (now the default). It creates one agent with a read permission on `mcp:github:*`, an endpoint that allows one request and denies another, and an audit route that shows both. The scaffolder also accepts a directory, `--template`, `--yes` and `--no-install`, and runs the package manager install. The CLI help, README and `init` output use `npx @glinr/theauth-cli`, fix a doubled scope in the Hono install line, and the CLI now depends on `@glinr/theauth-dashboard` so `dashboard` finds the dashboard files after an install from npm.
