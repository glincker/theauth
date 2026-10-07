# @glinr/theauth-ui

## 0.2.0

### Minor Changes

- 0fa5b1e: Remove the legacy KavachOS naming. The deprecated `Kavach*` and `createKavach` exports are gone: use `TheAuth*` and `createTheAuth`. Environment variables are now `THEAUTH_*`, webhook headers `X-TheAuth-*`, cookies and the default API route use `theauth`, and database tables are `theauth_*` (existing `kavach_*` tables are renamed in place by `createTables`, no data is lost). `Auth*` aliases remain deprecated.

## 0.1.0

### Minor Changes

- 94804ec: Launch release: promote core and primary client-facing packages to the 0.1 line.

  Highlights:

  - Stabilize package exports and build artifacts for launch.
  - Ship improved CLI version handling and launch docs.
  - Keep adapters/plugins/dashboard on existing release tracks for a separate coordinated versioning pass.
