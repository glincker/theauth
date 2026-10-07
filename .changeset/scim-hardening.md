---
"@glinr/theauth": minor
---

Harden the SCIM 2.0 server. List endpoints now accept the full RFC 7644 filter grammar through a real parser, with operators eq, ne, co, sw, ew, gt, ge, lt, le and pr, the and, or and not combinators, parentheses and value path selectors, plus sortBy and sortOrder. PATCH supports path expressions with value filters such as emails[type eq "work"].value, rejects changes to immutable attributes and caps a request at 1000 operations. A new opt in Me endpoint resolves the caller through a resolveSelf callback, and the Bulk endpoint returns a spec compliant 501. Every successful provisioning write can now be recorded in the audit log by passing audit with an agent id. The Enterprise User extension is supported and advertised in the Schemas endpoint, and the repo gains an Okta example and a compatibility table.
