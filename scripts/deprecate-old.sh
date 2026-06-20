#!/usr/bin/env bash
# Deprecate the old kavachos npm packages after publishing the new @theauth/* scope.
#
# Run AFTER:
#   1. Publishing @theauth/* packages to npm (e.g. `pnpm publish -r --access public`)
#   2. Verifying the new packages install cleanly in a fresh project
#
# Requires:
#   - npm login as the owner of the kavachos / @kavachos scope
#   - The new @theauth/* (or @glincker/*) packages already published
#
# Usage:
#   bash scripts/deprecate-old.sh
#   bash scripts/deprecate-old.sh --dry-run

set -euo pipefail

DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
  echo "[dry-run] no commands will be executed"
fi

# Update the right-hand side if you publish to @glincker instead of @theauth
NEW_SCOPE="@theauth"

# Old package names that need deprecating. Edit if the actual published set differs.
OLD_PACKAGES=(
  "kavachos"
  "@kavachos/core"
  "@kavachos/client"
  "@kavachos/react"
  "@kavachos/vue"
  "@kavachos/svelte"
  "@kavachos/expo"
  "@kavachos/electron"
  "@kavachos/cli"
  "@kavachos/dashboard"
  "@kavachos/gateway"
  "@kavachos/ui"
  "@kavachos/test-utils"
  "@kavachos/email"
  "@kavachos/discovery"
  "@kavachos/telemetry"
  "@kavachos/astro"
  "@kavachos/express"
  "@kavachos/fastify"
  "@kavachos/hono"
  "@kavachos/nestjs"
  "@kavachos/nextjs"
  "@kavachos/nextjs-auth"
  "@kavachos/nuxt"
  "@kavachos/prisma"
  "@kavachos/solidstart"
  "@kavachos/sveltekit"
  "@kavachos/tanstack"
  "create-kavachos-app"
)

for pkg in "${OLD_PACKAGES[@]}"; do
  # Determine the new package name
  if [[ "$pkg" == "kavachos" ]]; then
    new_name="theauth"
  elif [[ "$pkg" == "create-kavachos-app" ]]; then
    new_name="create-theauth-app"
  else
    new_name="${pkg/@kavachos/$NEW_SCOPE}"
  fi

  msg="This package has been renamed to ${new_name}. Please migrate. See https://github.com/glincker/theauth"

  echo ">> deprecating $pkg -> $new_name"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] npm deprecate \"$pkg\" \"$msg\""
  else
    npm deprecate "$pkg" "$msg" || echo "  (skip: $pkg may not exist or you lack publish rights)"
  fi
done

echo "Done. Verify on https://www.npmjs.com/package/<pkg-name>"
