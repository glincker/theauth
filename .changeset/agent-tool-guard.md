---
"@glinr/theauth": minor
---

Added `guardTool` and `guardTools`, which put the policy engine in front of any agent tool with an `execute` function, with no framework dependency. A denied call throws `ToolDeniedError`, a call that needs a human throws `ToolApprovalRequiredError` with the approval request id and tier, and a failed check throws `ToolGuardFailedError`. The tool never runs in those cases. Pass the `approvalId` option to retry an approved call: the guard hands it to `evaluate`, which spends it once. The `PolicyEngineConfig` type is now exported from the package root.
