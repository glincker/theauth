---
"@glinr/theauth": minor
---

Added signed audit checkpoints and portable receipts. `createCheckpoint` builds an RFC 6962 style Merkle tree over the chained audit rows and signs the tree head with Ed25519. `createInclusionProof`, `createConsistencyProof` and `createReceipt` produce proofs that `verifyInclusionProof`, `verifyConsistencyProof` and `verifyReceipt` check offline with only a public key. A receipt reveals the decision fields you pick and keeps the rest as salted commitments. Includes `generateCheckpointKeyPair`, `createEd25519Signer`, and a `CheckpointStore` interface with `createMemoryCheckpointStore`.
