---
"@glinr/theauth": patch
"@glinr/theauth-cli": patch
---

Trim trailing slashes with a scan instead of `replace(/\/+$/, "")`, which is quadratic on a long run of slashes (federation discovery URL, self-hosted provider presets, CLI token cache key). Match whitespace before the `>` in the codemod's closing script tag. Repeat the reserved attribute name check inline at each SCIM PATCH property write.
