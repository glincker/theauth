---
"@glinr/theauth": patch
---

Security hardening found in review. These fix issues in the unreleased 2.0 work, not in a published release.

- Approvals are bound to the action, resource and arguments the human approved. Spending one with different arguments is denied with `APPROVAL_ARGUMENTS_MISMATCH`. An approval created without arguments covers only an argument-less call.
- A delegation covering several actions no longer drops the parent's `requireApproval` for any covered action. Constraints are now inherited per action, and a grant is split when actions carry different constraints.
- An in-process guard that returns `undefined`, `null` or any non-verdict value now fails closed as a deny instead of an allow.
- An invalid `expiresAt` (Invalid Date, NaN, non-finite, wrong type) now throws a `ValidationError` at agent create, agent update and delegation grant, instead of being stored as NULL (never expires).
- `toleranceSec` must be a finite number between 0 and 3600. `httpGuard` rejects anything else at config time and the verify helpers fail closed.
- The guard HTTP client now enforces the 64 KiB response cap while streaming and aborts once exceeded.
