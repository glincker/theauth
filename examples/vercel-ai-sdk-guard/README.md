# Vercel AI SDK guard example

A runnable demo of `guardTool` in front of Vercel AI SDK tools. It runs in memory and
needs no model and no API key: the script calls the guarded tools the way the
framework runner does when a model asks for one.

This folder is not a workspace package. It has no `package.json`, so it adds
nothing to the lockfile. Install the dependencies in a scratch project of your own.

## Run

```bash
mkdir guard-demo && cd guard-demo
npm init -y && npm pkg set type=module
npm install @glinr/theauth ai zod better-sqlite3 drizzle-orm
npm install -D tsx typescript @types/node
# copy index.ts from this folder, then:
npx tsx index.ts
```

`guardTool` and `replayAgent` need a `@glinr/theauth` release that includes the
tool guard. Until it is published, point the dependency at a local build of `packages/core`.

## What it demonstrates

1. A small call is allowed and the tool runs.
2. A refund of 5000 USD matches a risk tier that requires approval. The guard
   opens an approval request and the tool does not run.
3. A human approves. The retry passes that `approvalId`, which is spent once. A
   second use is denied with `APPROVAL_ALREADY_USED`.
4. The decisions are read back from the hash chained audit log, and the chain verifies.

In `index.ts`, each tool is built with `tool()` from `ai` and then wrapped with `guardTool`. Pass the guarded tools as `tools` to `generateText` or `streamText`.

## Expected output

IDs vary per run.

```
[1] Small call is allowed
    { invoiceId: 'inv_1', total: 480 }

[2] Large refund escalates
    held, tier=large, approval request=apr_45134c1d-7bef-46a5-890b-fa9bf2de289f

[3] Human approves, the retry spends the approval once
    { refunded: 5000, invoiceId: 'inv_1' }
    second use denied: APPROVAL_ALREADY_USED

[4] Read the chained decision record
    #1 allowed execute tool:lookupInvoice (matched)
    #2 escalated execute tool:refund (POLICY_ESCALATION_REQUIRED)
    #3 allowed approval.request approval:apr_45134c1d-...
    #4 allowed approval.approve approval:apr_45134c1d-... approver=user-alice
    #5 allowed execute tool:refund (APPROVAL_CONSUMED) approver=user-alice
    #6 denied execute tool:refund (APPROVAL_ALREADY_USED)
    chain verified, 6 rows checked
```

## Notes

- Audit rows are written in the background, so the script waits briefly before
  it reads the record. In your own code, read the record when you need it, not
  in the same tick as the call.
- The demo owner row is inserted directly. In a real app human sign-in creates it.
- Typechecked and run against `ai` 7.0.142 and `zod` 4.6.7. Tool types change between major versions, so check yours.
