/**
 * W3C Verifiable Credential verification for TheAuth.
 *
 * Verifies credentials in both JWT and JSON-LD formats. Checks
 * signatures, expiry, and optional revocation status. Extracts
 * TheAuth-specific permissions from verified credentials.
 */

import { compactVerify, importJWK, errors as joseErrors, jwtVerify } from "jose";
import type { KavachError, Result } from "../mcp/types.js";
import type {
	CredentialFormat,
	ExtractedPermissions,
	VCVerifierConfig,
	VerifiableCredential,
	VerifiablePresentation,
	VerifiedCredential,
	VerifiedPresentation,
} from "./types.js";
import { VerifiableCredentialSchema, VerifiablePresentationSchema } from "./types.js";

// ─── Helpers ────────────────────────────────────────────────────────────────

function makeError(code: string, message: string, details?: Record<string, unknown>): KavachError {
	return { code, message, ...(details !== undefined ? { details } : {}) };
}

function getIssuerString(issuer: string | { id: string; name?: string }): string {
	if (typeof issuer === "string") return issuer;
	return issuer.id;
}

// ─── VC Verifier Interface ──────────────────────────────────────────────────

export interface VCVerifier {
	/** Verify a single credential (JWT string or JSON-LD object) */
	verifyCredential(
		vc: string | VerifiableCredential,
		publicKeyJwk?: JsonWebKey,
	): Promise<Result<VerifiedCredential>>;
	/** Verify a presentation containing multiple VCs */
	verifyPresentation(
		vp: string | VerifiablePresentation,
		publicKeyJwk?: JsonWebKey,
	): Promise<Result<VerifiedPresentation>>;
	/** Extract TheAuth permissions from a verified credential */
	extractPermissions(vc: VerifiableCredential): ExtractedPermissions;
}

// ─── Factory ────────────────────────────────────────────────────────────────

/**
 * Create a VC verifier that checks signatures, expiry, and revocation.
 *
 * The verifier accepts both JWT-encoded and JSON-LD credentials.
 * For JWT credentials, pass the compact JWS string. For JSON-LD
 * credentials with embedded proof, pass the credential object.
 */
export function createVCVerifier(config: VCVerifierConfig = {}): VCVerifier {
	const { resolveDidKey, checkRevocationStatus } = config;

	async function resolveKey(did: string, providedKey?: JsonWebKey): Promise<Result<JsonWebKey>> {
		if (providedKey) {
			return { success: true, data: providedKey };
		}

		if (resolveDidKey) {
			const resolved = await resolveDidKey(did);
			if (resolved) {
				return { success: true, data: resolved };
			}
		}

		return {
			success: false,
			error: makeError("VC_KEY_NOT_FOUND", `Could not resolve public key for DID: ${did}`),
		};
	}

	async function verifyJwtCredential(
		jwt: string,
		providedKey?: JsonWebKey,
	): Promise<Result<VerifiedCredential>> {
		try {
			// Decode the header to get the kid, then resolve the key
			const parts = jwt.split(".");
			if (parts.length !== 3) {
				return {
					success: false,
					error: makeError("VC_INVALID_JWT", "JWT must have three parts"),
				};
			}

			// First pass: decode without verification to extract issuer
			const payloadB64 = parts[1];
			if (!payloadB64) {
				return {
					success: false,
					error: makeError("VC_INVALID_JWT", "JWT payload is missing"),
				};
			}
			const rawPayload = JSON.parse(
				new TextDecoder().decode(
					Uint8Array.from(atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/")), (c) =>
						c.charCodeAt(0),
					),
				),
			) as Record<string, unknown>;

			const issuerDid = typeof rawPayload.iss === "string" ? rawPayload.iss : null;
			if (!issuerDid) {
				return {
					success: false,
					error: makeError("VC_NO_ISSUER", "JWT has no iss claim"),
				};
			}

			// Resolve key
			const keyResult = await resolveKey(issuerDid, providedKey);
			if (!keyResult.success) return keyResult;

			const publicKey = await importJWK(keyResult.data, "EdDSA");
			const { payload } = await jwtVerify(jwt, publicKey);

			const vcClaim = payload.vc as Record<string, unknown> | undefined;
			if (!vcClaim) {
				return {
					success: false,
					error: makeError("VC_MISSING_VC_CLAIM", "JWT does not contain a vc claim"),
				};
			}

			// Reconstruct the full credential from the JWT claims
			const credential: VerifiableCredential = {
				...(vcClaim as unknown as VerifiableCredential),
				issuer: issuerDid,
			};

			// Validate against schema
			const parsed = VerifiableCredentialSchema.safeParse(credential);
			if (!parsed.success) {
				return {
					success: false,
					error: makeError("VC_INVALID_CREDENTIAL", "Credential does not match W3C schema", {
						issues: parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`),
					}),
				};
			}

			// Check expiry
			if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
				return {
					success: false,
					error: makeError("VC_EXPIRED", "Credential has expired"),
				};
			}

			// Check revocation
			if (parsed.data.credentialStatus && checkRevocationStatus) {
				const revoked = await checkRevocationStatus(parsed.data.credentialStatus);
				if (revoked) {
					return {
						success: false,
						error: makeError("VC_REVOKED", "Credential has been revoked"),
					};
				}
			}

			return {
				success: true,
				data: {
					credential: parsed.data,
					format: "jwt" as CredentialFormat,
					issuer: issuerDid,
					issuedAt: new Date((payload.iat ?? 0) * 1000),
					expiresAt: payload.exp ? new Date(payload.exp * 1000) : null,
				},
			};
		} catch (err) {
			// Distinguish between expiry and other errors
			if (err instanceof joseErrors.JWTExpired) {
				return {
					success: false,
					error: makeError("VC_EXPIRED", "Credential has expired"),
				};
			}
			return {
				success: false,
				error: makeError(
					"VC_VERIFY_FAILED",
					err instanceof Error ? err.message : "Failed to verify JWT credential",
				),
			};
		}
	}

	async function verifyJsonLdCredential(
		vc: VerifiableCredential,
		providedKey?: JsonWebKey,
	): Promise<Result<VerifiedCredential>> {
		// Validate schema
		const parsed = VerifiableCredentialSchema.safeParse(vc);
		if (!parsed.success) {
			return {
				success: false,
				error: makeError("VC_INVALID_CREDENTIAL", "Credential does not match W3C schema", {
					issues: parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`),
				}),
			};
		}

		const credential = parsed.data;

		if (!credential.proof) {
			return {
				success: false,
				error: makeError("VC_NO_PROOF", "JSON-LD credential has no embedded proof"),
			};
		}

		if (!credential.proof.jws) {
			return {
				success: false,
				error: makeError("VC_NO_JWS", "Proof does not contain a JWS value"),
			};
		}

		const issuerDid = getIssuerString(credential.issuer);

		// Resolve key
		const keyResult = await resolveKey(issuerDid, providedKey);
		if (!keyResult.success) return keyResult;

		try {
			const publicKey = await importJWK(keyResult.data, "EdDSA");

			// Verify the JWS
			const { payload } = await compactVerify(credential.proof.jws, publicKey);

			// Compare signed content against current credential (minus proof)
			const { proof: _proof, ...vcWithoutProof } = credential;
			const signedContent = new TextDecoder().decode(payload);
			const currentContent = JSON.stringify(vcWithoutProof);

			if (signedContent !== currentContent) {
				return {
					success: false,
					error: makeError("VC_TAMPERED", "Credential content does not match the signed payload"),
				};
			}

			// Check expiry
			if (credential.expirationDate) {
				const expiry = new Date(credential.expirationDate);
				if (expiry <= new Date()) {
					return {
						success: false,
						error: makeError("VC_EXPIRED", "Credential has expired"),
					};
				}
			}

			// Check revocation
			if (credential.credentialStatus && checkRevocationStatus) {
				const revoked = await checkRevocationStatus(credential.credentialStatus);
				if (revoked) {
					return {
						success: false,
						error: makeError("VC_REVOKED", "Credential has been revoked"),
					};
				}
			}

			return {
				success: true,
				data: {
					credential,
					format: "json-ld" as CredentialFormat,
					issuer: issuerDid,
					issuedAt: new Date(credential.issuanceDate),
					expiresAt: credential.expirationDate ? new Date(credential.expirationDate) : null,
				},
			};
		} catch (err) {
			return {
				success: false,
				error: makeError(
					"VC_VERIFY_FAILED",
					err instanceof Error ? err.message : "Failed to verify JSON-LD credential",
				),
			};
		}
	}

	// ── Public API ────────────────────────────────────────────────────────

	async function verifyCredential(
		vc: string | VerifiableCredential,
		publicKeyJwk?: JsonWebKey,
	): Promise<Result<VerifiedCredential>> {
		if (typeof vc === "string") {
			return verifyJwtCredential(vc, publicKeyJwk);
		}
		return verifyJsonLdCredential(vc, publicKeyJwk);
	}

	async function verifyPresentation(
		vp: string | VerifiablePresentation,
		publicKeyJwk?: JsonWebKey,
	): Promise<Result<VerifiedPresentation>> {
		let presentation: VerifiablePresentation;

		if (typeof vp === "string") {
			// JWT-encoded presentation
			try {
				const parts = vp.split(".");
				if (parts.length !== 3 || !parts[1]) {
					return {
						success: false,
						error: makeError("VC_INVALID_JWT", "Presentation JWT must have three parts"),
					};
				}

				const payloadB64 = parts[1];
				const rawPayload = JSON.parse(
					new TextDecoder().decode(
						Uint8Array.from(atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/")), (c) =>
							c.charCodeAt(0),
						),
					),
				) as Record<string, unknown>;

				const issuerDid = typeof rawPayload.iss === "string" ? rawPayload.iss : null;
				if (!issuerDid) {
					return {
						success: false,
						error: makeError("VC_NO_ISSUER", "Presentation JWT has no iss claim"),
					};
				}

				const keyResult = await resolveKey(issuerDid, publicKeyJwk);
				if (!keyResult.success) return keyResult;

				const publicKey = await importJWK(keyResult.data, "EdDSA");
				const { payload } = await jwtVerify(vp, publicKey);

				const vpClaim = payload.vp as Record<string, unknown> | undefined;
				if (!vpClaim) {
					return {
						success: false,
						error: makeError("VC_MISSING_VP_CLAIM", "JWT does not contain a vp claim"),
					};
				}

				presentation = vpClaim as unknown as VerifiablePresentation;
			} catch (err) {
				return {
					success: false,
					error: makeError(
						"VC_VERIFY_FAILED",
						err instanceof Error ? err.message : "Failed to verify presentation JWT",
					),
				};
			}
		} else {
			presentation = vp;
		}

		// Validate schema
		const parsed = VerifiablePresentationSchema.safeParse(presentation);
		if (!parsed.success) {
			return {
				success: false,
				error: makeError("VC_INVALID_PRESENTATION", "Presentation does not match W3C schema", {
					issues: parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`),
				}),
			};
		}

		// Verify each credential in the presentation
		const verifiedCredentials: VerifiedCredential[] = [];
		for (const vc of parsed.data.verifiableCredential) {
			const result = await verifyCredential(vc, publicKeyJwk);
			if (!result.success) {
				return {
					success: false,
					error: makeError(
						"VC_PRESENTATION_CREDENTIAL_INVALID",
						`Failed to verify credential in presentation: ${result.error.message}`,
						{ originalError: result.error },
					),
				};
			}
			verifiedCredentials.push(result.data);
		}

		return {
			success: true,
			data: {
				presentation: parsed.data,
				credentials: verifiedCredentials,
				holder: parsed.data.holder ?? null,
			},
		};
	}

	function extractPermissions(vc: VerifiableCredential): ExtractedPermissions {
		const subject = vc.credentialSubject;
		return {
			agentId: subject.agentId ?? subject.id ?? null,
			permissions: subject.permissions ?? [],
			trustLevel: subject.trustLevel ?? null,
			delegationScope: subject.delegationScope ?? [],
		};
	}

	return {
		verifyCredential,
		verifyPresentation,
		extractPermissions,
	};
}
