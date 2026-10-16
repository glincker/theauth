---
"@glinr/theauth": minor
---

Add policy shrink: `analyzeUsage` compares an agent's effective permissions (including active delegations) with its recorded decisions, `suggestShrink` proposes a smaller set (with optional, bounded generalization), and `verifyShrink` and `previewPolicyChange` report which recorded decisions would flip for any proposed permission change. Reads audit rows in pages and never changes permissions.
