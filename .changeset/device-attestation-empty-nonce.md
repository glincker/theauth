---
"@glinr/theauth": patch
---

The Android Key Attestation, Apple App Attest and TPM 2.0 quote verifiers now refuse an empty string nonce, like the Go port does. An empty nonce used to pass the "nonce is missing" check, and a TPM quote with empty qualifying data would then match it.
