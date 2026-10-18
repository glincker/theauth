---
"@glinr/theauth": major
---

Security fix for SAML SSO. Upgrade if you use `sso.saml`. Every published release with SAML support is affected, including 1.2.0.

What was wrong:

- Signature checking could be bypassed. When the element named by the signature `Reference` could not be found, or `DigestValue` or `DigestMethod` was missing, the digest check was skipped and only `SignedInfo` was verified. The user identity was then read from the first matching element anywhere in the document, not from the signed element.
- The digest and `SignedInfo` were hashed from raw text with no canonicalization, unknown algorithms fell back to SHA-256, and SHA-1 was always accepted.
- `cert` was imported as a bare public key. A real X.509 certificate is not one, so with genuine IdP certificates verification may never have succeeded.
- `wantAuthnResponseSigned: false` turned signature checking off completely.
- `InResponseTo` was never enforced through the built-in routes, there was no assertion replay cache, and the IdP `Issuer` was never checked against a configured value.

What changed:

- New verifier: one `Reference` to a same-document `#id` that must be the element holding the signature, duplicate ids rejected, exactly enveloped-signature plus exclusive c14n, exclusive c14n 1.0 on the parsed tree, allowlisted algorithms, constant time digest comparison. Claims are read only from the verified Assertion.
- `cert` accepts an X.509 certificate (PEM or bare base64) or a public key PEM. RSA keys under 2048 bits are rejected.
- New required provider option `idpEntityId`. Logins fail with `SAML_CONFIG_ERROR` until it is set.
- `wantAuthnResponseSigned: false` is now a config error. The Response or the Assertion must be signed.
- `allowLegacySha1` (default `false`) for IdPs that still sign with SHA-1. `allowIdpInitiated` (default `false`) for unsolicited responses. `clockSkewSeconds` is limited to 0 through 300.
- `getSamlAuthUrl` stores the AuthnRequest id in secondary storage (feature `nonces`) and sends an opaque single-use `RelayState`. The ACS route passes it back, so `InResponseTo` is checked. Your own relay state is returned as `relayState` in the result. `handleSamlResponse` takes `{ relayState }` or `{ expectedRequestId }` as its third argument.
- Assertion ids are kept in a replay cache until the assertion expires.
- The XML parser rejects DOCTYPE, ENTITY, unknown entity references and duplicate attributes, enforces size, depth, attribute and element limits (`xmlLimits`), and rejects comments inside `NameID` and attribute values.
- `SAMLRequest` was URL-encoded twice in the redirect URL. Fixed.

Encrypted assertions and detached signatures are still not supported. See the SSO docs for the full list of checks and limits.
