---
"@glinr/theauth-client": patch
---

The session store no longer needs `AbortController`: runtimes that have `fetch` but not `AbortController` (Lynx's PrimJS) can refresh the session, and a late answer is still dropped. New Lynx page with the runtime needs and a storage recipe, checked against the Lynx docs and a stripped runtime, not on a device.
