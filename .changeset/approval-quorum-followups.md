---
"@glinr/theauth": patch
"@glinr/theauth-cli": minor
"@glinr/theauth-prisma": minor
---

Quorum approvals follow-ups. The Prisma adapter gains `requiredApprovals` on `TheAuthApprovalRequest`, a `TheAuthApprovalVote` model and `castApprovalVote` / `listApprovalVotes`, with the same single vote guarantee as core (composite primary key plus one conditional `updateMany`). A new `theauth approvals` command (list, show, approve, deny, request with `--required-approvals`) drives the admin API. The Python and Go clients send `requiredApprovals` and read `requiredApprovals`, `approvalsReceived` and `approvers`. Fixed: when concurrent votes pushed the count past the quorum, the completing call reported every counted approver and recorded itself as the responder. It now reports the first `requiredApprovals` approvers.
