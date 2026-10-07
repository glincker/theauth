# Releasing

Releases are automatic. You only write changesets and merge one PR.

1. **Add a changeset** with every user-facing change: `pnpm changeset`, pick the packages and the bump, and write the entry as a plain sentence. This text becomes the release notes.
2. **Merge your PR.** The `version-packages` workflow opens or updates a PR titled `chore: version packages` that applies all pending changesets (versions and CHANGELOG files).
3. **Merge the version PR.** `publish.yml` publishes every package whose version differs from npm. When it succeeds, `release.yml` tags `v<core version>` and creates the GitHub release with notes built by `scripts/release-notes.mjs`: highlights from the core changelog, an upgrade note for major bumps, a table of packages with npm and changelog links, install commands and a compare link. It then syncs the monthly release discussion.

To rebuild or fix a release, run the `Release` workflow manually with the tag. To preview notes locally: `node scripts/release-notes.mjs v0.6.0 --prev v0.5.0`.

Tags are created by `release.yml`, not by hand. The core version (`@glinr/theauth`) names the release; adapters and other packages are listed in its table with their own versions.
