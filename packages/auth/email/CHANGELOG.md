# @glinr/theauth-email

## 4.1.0

### Minor Changes

- 292ec38: Email and password sign-in now consults the core sign-in gate when the core exposes `ctx.signInGate`: a forced password change answers 403 `PASSWORD_RESET_REQUIRED` with a challenge, and a required second factor answers `{ twoFactorRequired: true, challenge }`. A completed password reset clears the forced change flag, and any password change revokes trusted devices. `auth.session.maxConcurrent` and `onLimit` are honored for sessions this package creates. `createEmailAuth` accepts `signInGate` and `sessionLimit` directly.

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
