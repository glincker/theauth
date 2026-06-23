/**
 * W3C Verifiable Credentials Data Model 2.0 types for TheAuth.
 *
 * Defines Zod-validated schemas for credentials, presentations,
 * proofs, and credential status. Agent-centric: the credential
 * subject carries agent identity, permissions, trust level, and
 * delegation scope.
 */

import { z } from "zod";

// ─── W3C VC Constants ────────────────────────────────────────────────────────

export const VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2";
export const VC_CONTEXT_V1 = "https://www.w3.org/2018/credentials/v1";
export const VC_TYPE_CREDENTIAL = "VerifiableCredential";
export const VC_TYPE_PRESENTATION = "VerifiablePresentation";

// TheAuth-specific credential types
export const AUTH_AGENT_CREDENTIAL = "AuthAgentCredential";
export const AUTH_PERMISSION_CREDENTIAL = "AuthPermissionCredential";
export const AUTH_DELEGATION_CREDENTIAL = "AuthDelegationCredential";

/** @deprecated Use {@link AUTH_AGENT_CREDENTIAL} instead. Will be removed in v3.0. */
export const KAVACH_AGENT_CREDENTIAL = AUTH_AGENT_CREDENTIAL;
/** @deprecated Use {@link AUTH_PERMISSION_CREDENTIAL} instead. Will be removed in v3.0. */
export const KAVACH_PERMISSION_CREDENTIAL = AUTH_PERMISSION_CREDENTIAL;
/** @deprecated Use {@link AUTH_DELEGATION_CREDENTIAL} instead. Will be removed in v3.0. */
export const KAVACH_DELEGATION_CREDENTIAL = AUTH_DELEGATION_CREDENTIAL;

// ─── Proof Types ─────────────────────────────────────────────────────────────

export const ProofSchema = z.object({
	type: z.enum(["Ed25519Signature2020", "JsonWebSignature2020"]),
	created: z.string(),
	verificationMethod: z.string(),
	proofPurpose: z.enum(["assertionMethod", "authentication"]),
	proofValue: z.string().optional(),
	jws: z.string().optional(),
});

export type Proof = z.infer<typeof ProofSchema>;

// ─── Credential Status ──────────────────────────────────────────────────────

export const CredentialStatusSchema = z.object({
	id: z.string(),
	type: z.string(),
	statusPurpose: z.enum(["revocation", "suspension"]),
	statusListIndex: z.number().int().nonnegative(),
	statusListCredential: z.string(),
});

export type CredentialStatus = z.infer<typeof CredentialStatusSchema>;

// ─── Credential Subject ─────────────────────────────────────────────────────

export const CredentialSubjectSchema = z
	.object({
		id: z.string().optional(),
		agentId: z.string().optional(),
		permissions: z.array(z.string()).optional(),
		trustLevel: z.number().min(0).max(1).optional(),
		delegationScope: z.array(z.string()).optional(),
		delegationChain: z
			.array(
				z.object({
					delegator: z.string(),
					delegatee: z.string(),
					permissions: z.array(z.string()),
					createdAt: z.string(),
				}),
			)
			.optional(),
		name: z.string().optional(),
		type: z.string().optional(),
	})
	// Passthrough preserves application-specific fields (e.g. audit subject fields)
	// so that signature verification can reconstruct the exact signed content.
	.passthrough();

export type CredentialSubject = z.infer<typeof CredentialSubjectSchema>;

// ─── Verifiable Credential ──────────────────────────────────────────────────

export const VerifiableCredentialSchema = z.object({
	"@context": z.array(z.string()).min(1),
	id: z.string().optional(),
	type: z.array(z.string()).min(1),
	issuer: z.union([z.string(), z.object({ id: z.string(), name: z.string().optional() })]),
	issuanceDate: z.string(),
	expirationDate: z.string().optional(),
	credentialSubject: CredentialSubjectSchema,
	credentialStatus: CredentialStatusSchema.optional(),
	proof: ProofSchema.optional(),
});

export type VerifiableCredential = z.infer<typeof VerifiableCredentialSchema>;

// ─── Verifiable Presentation ────────────────────────────────────────────────

export const VerifiablePresentationSchema = z.object({
	"@context": z.array(z.string()).min(1),
	id: z.string().optional(),
	type: z.array(z.string()).min(1),
	holder: z.string().optional(),
	verifiableCredential: z.array(VerifiableCredentialSchema).min(1),
	proof: ProofSchema.optional(),
});

export type VerifiablePresentation = z.infer<typeof VerifiablePresentationSchema>;

// ─── Issuer Config ──────────────────────────────────────────────────────────

export interface VCIssuerConfig {
	/** DID of the issuer (e.g. did:key:z6Mk...) */
	issuerDid: string;
	/** Private key JWK for signing credentials */
	privateKeyJwk: JsonWebKey;
	/** Public key JWK for verification method references */
	publicKeyJwk: JsonWebKey;
	/** Default credential lifetime in seconds. Default: 86400 (24 hours). */
	defaultTtl?: number;
	/** Credential status endpoint base URL (for revocation). Optional. */
	statusEndpoint?: string;
}

// ─── Verifier Config ────────────────────────────────────────────────────────

export interface VCVerifierConfig {
	/**
	 * Resolve a DID to its public key JWK.
	 * If not provided, only credentials with a known public key can be verified.
	 */
	resolveDidKey?: (did: string) => Promise<JsonWebKey | null>;
	/**
	 * Check credential revocation status.
	 * If not provided, revocation checks are skipped.
	 */
	checkRevocationStatus?: (status: CredentialStatus) => Promise<boolean>;
}

// ─── JWT VC Types ───────────────────────────────────────────────────────────

/** Claims embedded in a JWT-encoded Verifiable Credential */
export interface VCJwtPayload {
	iss: string;
	sub?: string;
	vc: Omit<VerifiableCredential, "proof">;
	iat: number;
	exp?: number;
	jti?: string;
}

/** The format a credential was issued in */
export type CredentialFormat = "jwt" | "json-ld";

/** Result of a successful credential verification */
export interface VerifiedCredential {
	credential: VerifiableCredential;
	format: CredentialFormat;
	issuer: string;
	issuedAt: Date;
	expiresAt: Date | null;
}

/** Result of a successful presentation verification */
export interface VerifiedPresentation {
	presentation: VerifiablePresentation;
	credentials: VerifiedCredential[];
	holder: string | null;
}

/** Extracted permissions from a verified credential */
export interface ExtractedPermissions {
	agentId: string | null;
	permissions: string[];
	trustLevel: number | null;
	delegationScope: string[];
}
