---
"@glinr/theauth": minor
"@glinr/theauth-cli": minor
---

Built in attestation verifiers for the device enrollment hook. `createAppleAppAttestVerifier` follows Apple's attestation object validation guide (CBOR object, certificate chain to the Apple App Attestation Root CA, nonce over authData and the client data hash, key id, App ID hash, counter, AAGUID) and binds the enrolled key through the client data. `createTpm2QuoteVerifier` checks a TPM 2.0 quote (restricted resident signing key, qualifying data equal to the nonce, RSASSA or ECDSA signature, PCR digest, optional certificate chain). Both use Web Crypto only and refuse on any doubt. The CLI gains `theauth device attest apple` and `theauth device attest tpm`. Tested against real fixtures: Apple's own sample plus two device recordings for App Attest, and real Google Compute Engine vTPM quotes for TPM. The IoT docs say what that does and does not cover.
