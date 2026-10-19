# @glinr/theauth-prisma

## 4.1.0

### Minor Changes

- 746da30: Quorum approvals follow-ups. The Prisma adapter gains `requiredApprovals` on `TheAuthApprovalRequest`, a `TheAuthApprovalVote` model and `castApprovalVote` / `listApprovalVotes`, with the same single vote guarantee as core (composite primary key plus one conditional `updateMany`). A new `theauth approvals` command (list, show, approve, deny, request with `--required-approvals`) drives the admin API. The Python and Go clients send `requiredApprovals` and read `requiredApprovals`, `approvalsReceived` and `approvers`. Fixed: when concurrent votes pushed the count past the quorum, the completing call reported every counted approver and recorded itself as the responder. It now reports the first `requiredApprovals` approvers.

### Patch Changes

- 96ae5ef: Widen the `@glinr/theauth` peer range from `<2.0.0` to `<3.0.0` so these packages install next to core 2.x without a peer warning.
- 8bff5af: The reference `schema.prisma` declares the hot path indexes from core migration 0014 (agent token hash, agent owner and status, delegation chain lookups, rate limit lookup, pending approvals, permissions by agent), with the same names as the SQL migration.

## 4.0.0

### Minor Changes

- 0fa5b1e: Remove the legacy KavachOS naming. The deprecated `Kavach*` and `createKavach` exports are gone: use `TheAuth*` and `createTheAuth`. Environment variables are now `THEAUTH_*`, webhook headers `X-TheAuth-*`, cookies and the default API route use `theauth`, and database tables are `theauth_*` (existing `kavach_*` tables are renamed in place by `createTables`, no data is lost). `Auth*` aliases remain deprecated.

### Patch Changes

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
