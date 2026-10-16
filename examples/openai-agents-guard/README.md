# OpenAI Agents SDK guard example

A runnable demo of `guardTool` in front of OpenAI Agents SDK tools. It runs in memory and
needs no model and no API key: the script calls the guarded tools the way the
framework runner does when a model asks for one.

This folder is not a workspace package. It has no `package.json`, so it adds
nothing to the lockfile. Install the dependencies in a scratch project of your own.

## Run

```bash
mkdir guard-demo && cd guard-demo
npm init -y && npm pkg set type=module
npm install @glinr/theauth @openai/agents zod better-sqlite3 drizzle-orm
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

In `index.ts`, the plain tool definition is guarded first and then passed to `tool()` from `@openai/agents`, with an `errorFunction` that returns the refusal text to the model. Pass the result in an agent's `tools` array.

## Expected output

IDs vary per run.

```
[1] Small refund is allowed
    { refunded: 20, invoiceId: 'inv_1' }

[2] Large refund escalates, the model sees the refusal text
    Tool "refund" needs human approval (tier large). Approval request apr_5955a527-... was opened. Do not retry until it is granted; tell the user it is waiting.
    approval request apr_5955a527-...

[3] Human approves, the retry spends the approval once
    { refunded: 5000, invoiceId: 'inv_1' }
    Tool "refund" was denied by policy (APPROVAL_ALREADY_USED). Do not retry this call.

[4] Read the chained decision record
    #1 allowed execute tool:refund (matched)
    #2 escalated execute tool:refund (POLICY_ESCALATION_REQUIRED)
    #3 allowed approval.request approval:apr_5955a527-...
    #4 allowed approval.approve approval:apr_5955a527-... approver=user-alice
    #5 allowed execute tool:refund (APPROVAL_CONSUMED) approver=user-alice
    #6 denied execute tool:refund (APPROVAL_ALREADY_USED)
    chain verified, 6 rows checked
```

## Notes

- Audit rows are written in the background, so the script waits briefly before
  it reads the record. In your own code, read the record when you need it, not
  in the same tick as the call.
- The demo owner row is inserted directly. In a real app human sign-in creates it.
- Typechecked and run against `@openai/agents` 0.20.0 and `zod` 4.6.7. Tool types change between major versions, so check yours.
