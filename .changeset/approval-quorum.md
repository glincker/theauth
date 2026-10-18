---
"@glinr/theauth": minor
"@glinr/theauth-dashboard": minor
---

Added quorum (two person) approvals. `approval.request({ requiredApprovals: 2 })`, `approval.requiredApprovals` and `approval.quorum(request)` make a request need N distinct approvers (1 to 10, default 1). Approvers must differ from the requester and from each other, one denial ends the request, each approval writes its own audit row, and the argument bound hash, single spend and expiry apply to the whole quorum. `ApprovalQuorumError` carries the code `SELF_APPROVAL`, `DUPLICATE_APPROVER` or `APPROVER_REQUIRED`.

The admin API `POST /approvals` takes `requiredApprovals`, and approve answers `status: "pending"` until the quorum is complete. The `approval.pending` webhook payload adds `requiredApprovals` and `approvalsReceived`, and a new `approval.vote` event reports progress. The dashboard inbox shows "1 of 2 approvals". Adds migration 0013 (`required_approvals` column and `theauth_approval_votes` table).
