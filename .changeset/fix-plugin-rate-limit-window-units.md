---
"@glinr/theauth": patch
---

Fix plugin endpoint rate limit windows in the anonymous, device, SIWE, and OAuth proxy plugins. They declared `rateLimit.window` in milliseconds while the plugin router reads it as seconds, so a 60_000 window lasted about 16 hours. The window is now in seconds, and the `PluginEndpoint` type documents the unit.
