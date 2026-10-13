---
"@glinr/theauth": patch
"@glinr/theauth-plugin-discovery": patch
---

Require `drizzle-orm` 0.45.2 or newer. Earlier versions do not escape SQL identifiers correctly, which allows SQL injection when an identifier is built from untrusted input (GHSA advisory for drizzle-orm below 0.45.2). The ranges in the create-theauth-app template and the examples are bumped too.
