# @glinr/theauth-ui

## 0.3.0

### Minor Changes

- 640cd9f: Browser passkey client for the TypeScript server. `createPasskeyClient` runs registration and sign-in against the passkey plugin routes, with conditional UI (autofill) support, and `SignIn` takes a `passkeyClient` prop for a passkey button and autofill suggestions.
- 3a041af: Accessibility pass on the default components. Errors are announced (`role="alert"`), field errors are linked to their input with `aria-describedby` and `aria-invalid`, the loading button sets `aria-busy`, the verification code digits and backup code input have accessible names inside a labelled group, and the auth card is a region named by its title. The default slots now live in one shared module instead of four copies.

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
