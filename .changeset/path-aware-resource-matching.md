---
"@glinr/theauth": minor
"@glinr/theauth-cli": minor
---

Opt in path aware resource matching: `resourceMatching: "path"` on `createTheAuth` (and `policy.resourceMatching` for the policy engine). Inside a colon segment `/` separates path segments, `*` matches one, `**` matches one or more, never an empty, `.` or `..` segment. The default is unchanged. Device bundles carry the mode (`rm` claim), `theauth ros2 export` takes `--resource-matching path` and `--single-level skip|widen`, `--robot` includes delegated permissions, and `--enclave-cert` sets the grant window from the certificate.

Security fix: the delegation subset check accepted a child resource longer than an exact parent resource (parent `tool:db`, child `tool:db:secrets`), which gave the child access the parent did not have. It now uses the runtime matcher. Also, with the default matching, `devices.register` and `devices.update` refuse a `*` that is not the last segment of a device resource.
