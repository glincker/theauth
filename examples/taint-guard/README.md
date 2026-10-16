# Taint guard example

A runnable demo of provenance labels with `guardTool`. It runs in memory and needs no model and no API key.

This folder is not a workspace package. It has no `package.json`. Install the dependencies in a scratch project of your own.

## Run

```bash
mkdir taint-demo && cd taint-demo
npm init -y && npm pkg set type=module
npm install @glinr/theauth better-sqlite3 drizzle-orm
npm install -D tsx typescript @types/node
# copy index.ts from this folder, then:
npx tsx index.ts
```

It needs a `@glinr/theauth` release that includes the taint guard. Until then, point the dependency at a local build of `packages/core`.

## What it shows

1. `fetch_page` runs and its result is registered as `tool_output:fetch_page`.
2. The model copies an address from the page into `send_email`. The tracker finds the string, the rule forbids `tool_output:*` on `recipient`, and the guard opens an approval request instead of sending.
3. A recipient with no labels passes unchanged.
4. A human approves and the retry spends the approval once.

Labels are only as good as the host's tagging. See `docs/taint-guard.mdx` for the limits.
