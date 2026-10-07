# @glinr/theauth-cli

## 0.2.0

### Minor Changes

- 02a8500: Add `theauth codemod rename`, a dry-run-by-default codemod that migrates `Kavach*` identifiers, old import paths and `KAVACH_*` env vars to their TheAuth names, and reports `X-Kavach-` headers, `kavach_` table names and other leftover mentions for manual review. Pass `--write` to apply and `--include-env` to also rewrite `.env*` files and docs.
- 0fa5b1e: Remove the legacy KavachOS naming. The deprecated `Kavach*` and `createKavach` exports are gone: use `TheAuth*` and `createTheAuth`. Environment variables are now `THEAUTH_*`, webhook headers `X-TheAuth-*`, cookies and the default API route use `theauth`, and database tables are `theauth_*` (existing `kavach_*` tables are renamed in place by `createTables`, no data is lost). `Auth*` aliases remain deprecated.

### Patch Changes

- Updated dependencies [960fe89]
- Updated dependencies [dfd31f9]
- Updated dependencies [5e53bdb]
- Updated dependencies [0fa5b1e]
- Updated dependencies [9861742]
  - @glinr/theauth@0.6.0
  - @glinr/theauth-hono@4.0.0

## 0.1.5

### Patch Changes

- Updated dependencies
  - @glinr/theauth@0.5.0
  - @glinr/theauth-hono@4.0.0

## 0.1.4

### Patch Changes

- Updated dependencies
  - theauth@0.4.2
  - @glinr/theauth-hono@3.0.2

## 0.1.3

### Patch Changes

- Updated dependencies
  - theauth@0.4.1
  - @glinr/theauth-hono@3.0.1

## 0.1.2

### Patch Changes

- Updated dependencies
  - theauth@0.4.0
  - @glinr/theauth-hono@3.0.0

## 0.1.1

### Patch Changes

- Updated dependencies
  - theauth@0.3.0
  - @glinr/theauth-hono@2.0.0

## 0.1.0

### Minor Changes

- 94804ec: Launch release: promote core and primary client-facing packages to the 0.1 line.

  Highlights:

  - Stabilize package exports and build artifacts for launch.
  - Ship improved CLI version handling and launch docs.
  - Keep adapters/plugins/dashboard on existing release tracks for a separate coordinated versioning pass.

### Patch Changes

- Updated dependencies [94804ec]
- Updated dependencies [94804ec]
  - theauth@0.1.0
  - @glinr/theauth-hono@1.0.0
