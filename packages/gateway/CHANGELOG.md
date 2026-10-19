# @glinr/theauth-gateway

## 4.2.0

### Minor Changes

- fe7e6c6: Input provenance end to end.

  - Content hashes in `input_provenance` are now HMAC-SHA-256 under an HKDF subkey of the audit key (version tag `hv: 2`). Old plain hashes still match. `hashInputContent(content, auditKey)` takes the key now, `hashInputContentPlain` is the old function (breaking for callers that hashed themselves, see `docs/upgrading-to-2.mdx`).
  - `audit.query({ provenance: { content } })` hashes on the server and matches keyed and plain rows. `AuditEntry.inputs` exposes the recorded sources.
  - `POST /authorize` and `POST /authorize/token` accept `inputs` or a `TheAuth-Inputs` header. `GET /audit` takes `provenanceKind`, `provenanceHash` and `provenanceContent`. `sdks/openapi.json` is regenerated.
  - Gateway reads `TheAuth-Inputs`, records it on permission checks and audit entries, and strips it before the upstream. The admin MCP server reads `_meta["io.theauth/inputs"]` and `query_audit` takes provenance filters.
  - `theauth audit query` with `--provenance <kind>[:<hash>]` and `--input-content`, and an Inputs column with chips on the dashboard audit page.
  - `policy.taint.inputLabels` (off by default) turns the kinds of `context.inputs` into `input:<kind>` call labels, so a taint rule can hold a tool such as `tool:exec` for approval after a retrieved document was in context.

### Patch Changes

- 96ae5ef: Widen the `@glinr/theauth` peer range from `<2.0.0` to `<3.0.0` so these packages install next to core 2.x without a peer warning.

## 4.1.0

### Minor Changes

- bf41bbb: Add `theauth dev` (zero-config local first run), a Cloudflare Workers template, an opt-in `adminApi` plugin with an admin MCP server (read-only by default, writes gated by approval), a black-box agent-auth conformance suite, and LangGraph and Mastra approval wrappers.

  Breaking behavior in the gateway: the client `Authorization` and `DPoP` headers are no longer forwarded to the upstream by default. Opt out with `--forward-auth` or `stripAuthHeader: false`. The gateway also gains an MCP mode, a 10 MiB request body limit, a 30 second upstream header timeout, and hop-by-hop and `X-Forwarded-*` header handling. Core gains a browser-safe `@glinr/theauth/browser` entry.

## 4.0.2

### Patch Changes

- 1fa2338: Resolve the client IP through the trusted proxy helper.
- 1fa2338: Expose trustedProxy in the gateway config file and CLI.

## 4.0.1

### Patch Changes

- 8997cae: Package metadata: add `engines` (Node 20+) and npm provenance to `publishConfig`, refresh the CLI description and keywords, and document MCP client setup in the gateway README.

## 4.0.0

### Minor Changes

- 0fa5b1e: Remove the legacy KavachOS naming. The deprecated `Kavach*` and `createKavach` exports are gone: use `TheAuth*` and `createTheAuth`. Environment variables are now `THEAUTH_*`, webhook headers `X-TheAuth-*`, cookies and the default API route use `theauth`, and database tables are `theauth_*` (existing `kavach_*` tables are renamed in place by `createTables`, no data is lost). `Auth*` aliases remain deprecated.

### Patch Changes

- c2b5daf: The gateway CLI now enables agents when it creates its TheAuth instance, so a fresh database gets the agent, audit and related tables at startup and the first agent call no longer fails with "no such table". The legacy table rename step in core is unchanged.
- Updated dependencies [960fe89]
- Updated dependencies [dfd31f9]
- Updated dependencies [5e53bdb]
- Updated dependencies [0fa5b1e]
- Updated dependencies [9861742]
  - @glinr/theauth@0.6.0

## 3.0.3

### Patch Changes

- Updated dependencies
  - @glinr/theauth@0.5.0

## 3.0.2

### Patch Changes

- Updated dependencies
  - theauth@0.4.2

## 3.0.1

### Patch Changes

- Updated dependencies
  - theauth@0.4.1

## 3.0.0

### Patch Changes

- Updated dependencies
  - theauth@0.4.0

## 2.0.0

### Patch Changes

- Updated dependencies
  - theauth@0.3.0

## 1.0.0

### Major Changes

- 94804ec: Launch wave B: explicit major alignment for adapters/plugins after core moves to the 0.1 line.

  Why major:

  - These packages are pre-1.0 and depend on core package version semantics.
  - Core 0.0.x -> 0.1.x is treated as breaking for dependent package versioning.

  Operator notes:

  - Publish this wave separately from the core/client 0.1.0 wave.
  - Keep `@glinr/theauth-dashboard` on its independent track.

### Patch Changes

- Updated dependencies [94804ec]
  - theauth@0.1.0
