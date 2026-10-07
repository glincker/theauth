---
"@glinr/theauth-cli": minor
---

Add `theauth codemod rename`, a dry-run-by-default codemod that migrates `Kavach*` identifiers, old import paths and `KAVACH_*` env vars to their TheAuth names, and reports `X-Kavach-` headers, `kavach_` table names and other leftover mentions for manual review. Pass `--write` to apply and `--include-env` to also rewrite `.env*` files and docs.
