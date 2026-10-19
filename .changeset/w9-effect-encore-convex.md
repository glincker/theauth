---
"@glinr/theauth": patch
---

Docs: Effect (3 and 4), Encore.ts and Convex integration recipes, each run against the real framework. They use the core HTTP handler, so there is no new package. Convex verifies theAuth tokens through a custom JWT provider, because theAuth needs a SQL database that Convex does not offer.
