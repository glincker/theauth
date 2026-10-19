---
"@glinr/theauth": minor
"@glinr/theauth-cli": minor
"@glinr/theauth-dashboard": minor
---

Device attestation goes further. A permission can now demand a hardware attested device: `constraints.attestation` takes `minSecurityLevel` (`hardware` or `strongbox`), `bootState` and `appIds`, and is decided against facts the server derives from the verified claims stored at enrollment (`attestationFacts`). It applies in `device.authorize`, in signed offline bundles (the new `att` claim) and in delegation (a child can only narrow it), fails closed for agents, users and devices without evidence, and denies with the new code `attestation_required`. The HTTP permission schemas accept it and reject unknown fields.

Apple App Attest: `verifyAppleAssertion` checks an assertion (signature over `authenticatorData` and the client data hash, `rpIdHash`, counter), `device.verifyAppAssertion` runs it for an enrolled device and advances `theauth_devices.app_attest_counter` with one conditional update (migration 0015), so the same assertion works once. `verifyAppleReceipt` checks Apple's fraud receipt (CMS signature, chain to Apple Root CA G3, app, key, expiry) and returns the risk metric. The verifier now returns the `attestedPublicKey` claim. Tested on real recordings from veehaitch/devicecheck-appattest and block/buzz.

TPM 2.0: `tpm2MakeCredential` and `device.tpmActivationChallenge` (route `POST /device/tpm-activation`) run the credential activation handshake, and `createTpm2CertifyVerifier` checks TPM2_Certify of the enrolled key plus the activation. Credential blobs were accepted by TPM2_ActivateCredential on a software TPM (swtpm) for RSA and ECC endorsement keys.

The dashboard shows verified attestation claims in the device detail panel. `theauth device attest` gains `apple-assertion` and `apple-receipt` and prints the policy facts of accepted evidence.
