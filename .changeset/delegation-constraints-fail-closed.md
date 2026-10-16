---
"@glinr/theauth": patch
---

Delegation constraints now fail closed when a child's argument patterns, IP allowlist or time window do not overlap the parent's. Before, the parent's wider value was kept and the child's restriction was silently dropped. The narrowed result now denies every call. Overnight time windows that are not identical to the other window also deny instead of falling back to the parent's.
