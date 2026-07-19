## Summary

<!-- What does this PR do and why? One to three sentences. -->

## Type of change

- [ ] Bug fix (non-breaking, fixes an issue)
- [ ] New feature (non-breaking, adds functionality)
- [ ] Breaking change (fix or feature that changes existing behavior)
- [ ] Refactor (no behavior change)
- [ ] Docs / examples only
- [ ] Chore (deps, CI, tooling)

## Related issues

<!-- Link issues: "Closes #123" or "Fixes #456" -->

## Test plan

Which commands did you run to verify this change?

```bash
pnpm --filter @glinr/<package> test
pnpm typecheck
pnpm lint
```

- [ ] Unit tests pass locally
- [ ] New behavior has test coverage
- [ ] Manual verification steps (describe below if needed)

## Public API impact

- [ ] No public API change
- [ ] Additive change (new exports, new options)
- [ ] Breaking change (removed/renamed exports, changed option types)

If breaking: describe the migration path.

## Database migration

- [ ] No migration needed
- [ ] Migration file added in `packages/core/migrations/`

## Framework adapter impact

- [ ] No adapter changes
- [ ] Adapter(s) affected: <!-- list them -->

If adapters are affected, confirm you tested against the relevant one.

## Documentation updated

- [ ] Not needed (internal change)
- [ ] Updated inline JSDoc / types
- [ ] Updated `docs/` or `docs-site/`
- [ ] External docs update needed (link issue or PR)

## Em-dash check

- [ ] No em dashes (--) or en dashes (-) in any added text (code, comments, docs, changelogs)

## Checklist

- [ ] Tests pass (`pnpm test`)
- [ ] Types check (`pnpm typecheck`)
- [ ] Lint clean (`pnpm lint`)
- [ ] No new `any` types introduced
- [ ] No `console.log` left in production code
- [ ] Changeset added if user-visible (`pnpm changeset`)
