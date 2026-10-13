# @glinr/theauth-dashboard

## 0.3.0

### Minor Changes

- 4f33ad2: The dashboard no longer keeps its secret in `sessionStorage`. `POST /api/dashboard/auth` with the secret sets an HttpOnly, SameSite=Strict session cookie that lasts eight hours, `GET` reports whether it is valid and `DELETE` signs out.

### Patch Changes

- 3a041af: Accessibility pass on the default components. Errors are announced (`role="alert"`), field errors are linked to their input with `aria-describedby` and `aria-invalid`, the loading button sets `aria-busy`, the verification code digits and backup code input have accessible names inside a labelled group, and the auth card is a region named by its title. The default slots now live in one shared module instead of four copies.

## 0.2.0

### Minor Changes

- 0fa5b1e: Remove the legacy KavachOS naming. The deprecated `Kavach*` and `createKavach` exports are gone: use `TheAuth*` and `createTheAuth`. Environment variables are now `THEAUTH_*`, webhook headers `X-TheAuth-*`, cookies and the default API route use `theauth`, and database tables are `theauth_*` (existing `kavach_*` tables are renamed in place by `createTables`, no data is lost). `Auth*` aliases remain deprecated.
