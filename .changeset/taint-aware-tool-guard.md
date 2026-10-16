---
"@glinr/theauth": minor
---

Added a taint-aware (information flow) tool guard. Tool arguments can carry provenance labels, given through the new `provenance` and `tracker` options of `guardTool`/`guardTools`, through `tainted()` values, or through a `ProvenanceTracker` that registers tool results as `tool_output:<tool>`. A new `policy.taint` config restricts which labels may flow into which tools with `forbid` and `require` rules, per tool or per argument, and either escalates for approval (reusing the single use `approvalId` flow) or denies with `POLICY_TAINT_VIOLATION`. The labels and the verdict are written to the hash chained decision record's `input_provenance` automatically. Behavior with no labels supplied is unchanged. New helpers: `tainted`, `untaint`, `labelsOf`, `deriveLabels`, `matchLabel`, `ProvenanceTracker`.
