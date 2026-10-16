# Policy shrink example

A runnable demo of `analyzeUsage`, `suggestShrink` and `previewPolicyChange`. It runs in memory and needs no model and no API key. The script gives one agent seven grants, sends 498 calls through `authorize()` so real decision rows are written, then reports which grants were never used and what a smaller set would change.

This folder is not a workspace package. It has no `package.json`, so it adds nothing to the lockfile. Install the dependencies in a scratch project of your own.

## Run

```bash
mkdir shrink-demo && cd shrink-demo
npm init -y && npm pkg set type=module
npm install @glinr/theauth better-sqlite3 drizzle-orm
npm install -D tsx typescript @types/node
# copy index.ts from this folder, then:
npx tsx index.ts
```

## What you should see

Ten single-action grants, five of them used, five never used (`mcp:github:repos write`, `mcp:github:pulls read`, `tool:db:users delete`, `tool:mail send`, `tool:billing *`). The proposal keeps three permissions. Because the script passes `minObservations: 5`, the three `query` calls on `tool:db:users` are reported as newly denied, which is the line to review before applying anything. Pass `minObservations: 1` (the default) to keep every historical allow.

The functions only read audit rows. The script never changes the agent's permissions.
