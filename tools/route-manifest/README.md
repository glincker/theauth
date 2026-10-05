# route-manifest

Prints the chi routes of a theauth-go checkout as JSON. Standard library only; it never imports the Go repo.

```sh
go run . -dir ../../../theauth-go -commit "$(git -C ../../../theauth-go rev-parse HEAD)" > /tmp/routes.json
```

The TS drift test (`packages/client/tests/route-drift.test.ts`) reads the checked-in `packages/client/routes.manifest.json`, not this output. To refresh it, run the command above, then copy the `routes` for the `/auth` surface the client uses into the manifest and update `source.commit`. The scan is syntactic: it flattens `r.Route("/x", func...)` nesting, but routers mounted through helper functions (`/auth/totp`, `/auth/webauthn`, `/auth/email-password`, `/auth/device`, `/auth/tokens`) appear under the bare mount, so prefix those by hand. Admin, SCIM, SAML and org routes are out of scope for the client.

Suggested Go-side regeneration: run this from a CI step in theauth-go and fail when `git diff --exit-code` on the committed copy shows drift.
