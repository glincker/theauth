---
"@glinr/theauth": minor
---

`authorize()` and `policy.evaluate()` now accept an optional `approvalId`. When the matched permission requires approval, the call verifies that the approval request is approved, belongs to the same agent, matches the action and resource exactly, is not expired and was not used, then spends it with a single conditional update and allows the call. Failures are denied with `APPROVAL_NOT_FOUND`, `APPROVAL_NOT_APPROVED`, `APPROVAL_MISMATCH`, `APPROVAL_EXPIRED` or `APPROVAL_ALREADY_USED`. The audit row records `approver_id` and the approval id. A nullable `consumed_at` column is added to the approval requests table automatically.
