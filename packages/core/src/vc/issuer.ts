/**
 * W3C Verifiable Credential issuance for TheAuth.
 *
 * Issues VCs as JWT (compact JWS) or JSON-LD with embedded proof.
 * Credentials encode agent identity, permissions, and delegation chains
 * so agents can prove their capabilities to any verifier without
 * a network call back to TheAuth.
 */

import { importJWK, SignJWT } from "jose";
import { generateId } from "../crypto/web-crypto.js";
import type { KavachError, Result } from "../mcp/types.js";
import type {
	CredentialFormat,
	CredentialSubject,
	Proof,
	VCIssuerConfig,
	VerifiableCredential,
} from "./types.js";
import {
	KAVACH_AGENT_CREDENTIAL,
	KAVACH_DELEGATION_CREDENTIAL,
	KAVACH_PERMISSION_CREDENTIAL,
	VC_CONTEXT_V2,
	VC_TYPE_CREDENTIAL,
} from "./types.js";

// ─── Constants ──────────────────────────────────────────────────────────────

const DEFAULT_TTL_SECONDS = 86400; // 24 hours

// ─── Helpers ────────────────────────────────────────────────────────────────

function makeError(code: string, message: string, details?: Record<string, unknown>): KavachError {
	return { code, message, ...(details !== undefined ? { details } : {}) };
}

function nowISO(): string {
	return new Date().toISOString();
}

function futureISO(seconds: number): string {
	return new Date(Date.now() + seconds * 1000).toISOString();
}

// ─── Agent Credential Input ─────────────────────────────────────────────────

export interface IssueAgentCredentialInput {
	/** Agent ID (used as credentialSubject.id and sub claim) */
	agentId: string;
	/** Agent name */
	name?: string;
	/** Agent type (e.g. "autonomous", "supervised") */
	agentType?: string;
	/** Permissions granted to this agent */
	permissions?: string[];
	/** Trust score between 0 and 1 */
	trustLevel?: number;
	/** Credential lifetime in seconds. Overrides the issuer default. */
	ttl?: number;
	/** Output format. Default: "jwt". */
	format?: CredentialFormat;
}

// ─── Permission Credential Input ────────────────────────────────────────────

export interface IssuePermissionCredentialInput {
	/** Agent DID or ID that receives the permissions */
	agentId: string;
	/** Permissions being granted */
	permissions: string[];
	/** Credential lifetime in seconds. Overrides the issuer default. */
	ttl?: number;
	/** Output format. Default: "jwt". */
	format?: CredentialFormat;
}

// ─── Delegation Credential Input ────────────────────────────────────────────

export interface DelegationLink {
	delegator: string;
	delegatee: string;
	permissions: string[];
	createdAt: string;
}

export interface IssueDelegationCredentialInput {
	/** The agent at the end of the delegation chain */
	agentId: string;
	/** Ordered delegation chain from root to leaf */
	chain: DelegationLink[];
	/** Scope of delegated permissions (subset of original) */
	delegationScope?: string[];
	/** Credential lifetime in seconds. Overrides the issuer default. */
	ttl?: number;
	/** Output format. Default: "jwt". */
	format?: CredentialFormat;
}

// ─── VC Issuer Interface ────────────────────────────────────────────────────

export interface VCIssuer {
	/** Issue a VC encoding agent identity, permissions, and trust score */
	issueAgentCredential(
		input: IssueAgentCredentialInput,
	): Promise<Result<{ credential: VerifiableCredential; jwt?: string }>>;
	/** Issue a VC for specific permission grants */
	issuePermissionCredential(
		input: IssuePermissionCredentialInput,
	): Promise<Result<{ credential: VerifiableCredential; jwt?: string }>>;
	/** Issue a VC encoding a delegation chain */
	issueDelegationCredential(
		input: IssueDelegationCredentialInput,
	): Promise<Result<{ credential: VerifiableCredential; jwt?: string }>>;
	/** The DID of this issuer */
	readonly issuerDid: string;
}

// ─── Factory ────────────────────────────────────────────────────────────────

/**
 * Create a VC issuer bound to a specific DID and keypair.
 *
 * The issuer can produce credentials in JWT or JSON-LD format.
 * JWT credentials are signed as a compact JWS with the VC embedded
 * in the `vc` claim. JSON-LD credentials carry an embedded proof.
 */
export function createVCIssuer(config: VCIssuerConfig): VCIssuer {
	const { issuerDid, privateKeyJwk, defaultTtl = DEFAULT_TTL_SECONDS } = config;

	const kid = `${issuerDid}#${issuerDid.split(":").pop() ?? "key-1"}`;

	async function signAsJwt(
		credential: VerifiableCredential,
		subject: string | undefined,
		ttl: number,
	): Promise<Result<{ credential: VerifiableCredential; jwt: string }>> {
		try {
			const key = await importJWK(privateKeyJwk, "EdDSA");

			// Strip proof from the VC when embedding in JWT — the JWT signature is the proof
			const { proof: _proof, ...vcWithoutProof } = credential;

			const builder = new SignJWT({
				vc: vcWithoutProof,
			})
				.setProtectedHeader({ alg: "EdDSA", kid, typ: "JWT" })
				.setIssuer(issuerDid)
				.setIssuedAt()
				.setExpirationTime(Math.floor(Date.now() / 1000) + ttl);

			if (credential.id) {
				builder.setJti(credential.id);
			}
			if (subject) {
				builder.setSubject(subject);
			}

			const jwt = await builder.sign(key);
			return { success: true, data: { credential, jwt } };
		} catch (err) {
			return {
				success: false,
				error: makeError(
					"VC_SIGN_FAILED",
					err instanceof Error ? err.message : "Failed to sign credential as JWT",
				),
			};
		}
	}

	async function signAsJsonLd(
		credential: VerifiableCredential,
	): Promise<Result<{ credential: VerifiableCredential }>> {
		try {
			const key = await importJWK(privateKeyJwk, "EdDSA");

			// Create a JWS over the credential without proof
			const { proof: _proof, ...vcWithoutProof } = credential;
			const payload = new TextEncoder().encode(JSON.stringify(vcWithoutProof));

			const { CompactSign } = await import("jose");
			const jws = await new CompactSign(payload)
				.setProtectedHeader({ alg: "EdDSA", kid })
				.sign(key);

			const proof: Proof = {
				type: "JsonWebSignature2020",
				created: nowISO(),
				verificationMethod: kid,
				proofPurpose: "assertionMethod",
				jws,
			};

			const signedCredential: VerifiableCredential = {
				...credential,
				proof,
			};

			return { success: true, data: { credential: signedCredential } };
		} catch (err) {
			return {
				success: false,
				error: makeError(
					"VC_SIGN_FAILED",
					err instanceof Error ? err.message : "Failed to sign credential as JSON-LD",
				),
			};
		}
	}

	function buildCredential(
		types: string[],
		subject: CredentialSubject,
		ttl: number,
		expirationDate?: string,
	): VerifiableCredential {
		return {
			"@context": [VC_CONTEXT_V2],
			id: `urn:uuid:${generateId()}`,
			type: [VC_TYPE_CREDENTIAL, ...types],
			issuer: issuerDid,
			issuanceDate: nowISO(),
			expirationDate: expirationDate ?? futureISO(ttl),
			credentialSubject: subject,
		};
	}

	async function signCredential(
		credential: VerifiableCredential,
		subject: string | undefined,
		ttl: number,
		format: CredentialFormat,
	): Promise<Result<{ credential: VerifiableCredential; jwt?: string }>> {
		if (format === "jwt") {
			return signAsJwt(credential, subject, ttl);
		}
		return signAsJsonLd(credential);
	}

	// ── Public API ────────────────────────────────────────────────────────

	async function issueAgentCredential(
		input: IssueAgentCredentialInput,
	): Promise<Result<{ credential: VerifiableCredential; jwt?: string }>> {
		const {
			agentId,
			name,
			agentType,
			permissions,
			trustLevel,
			ttl = defaultTtl,
			format = "jwt",
		} = input;

		if (!agentId) {
			return {
				success: false,
				error: makeError("VC_INVALID_INPUT", "agentId is required"),
			};
		}

		if (trustLevel !== undefined && (trustLevel < 0 || trustLevel > 1)) {
			return {
				success: false,
				error: makeError("VC_INVALID_INPUT", "trustLevel must be between 0 and 1"),
			};
		}

		const subject: CredentialSubject = {
			id: agentId,
			agentId,
			...(name !== undefined ? { name } : {}),
			...(agentType !== undefined ? { type: agentType } : {}),
			...(permissions !== undefined ? { permissions } : {}),
			...(trustLevel !== undefined ? { trustLevel } : {}),
		};

		const credential = buildCredential([KAVACH_AGENT_CREDENTIAL], subject, ttl);
		return signCredential(credential, agentId, ttl, format);
	}

	async function issuePermissionCredential(
		input: IssuePermissionCredentialInput,
	): Promise<Result<{ credential: VerifiableCredential; jwt?: string }>> {
		const { agentId, permissions, ttl = defaultTtl, format = "jwt" } = input;

		if (!agentId) {
			return {
				success: false,
				error: makeError("VC_INVALID_INPUT", "agentId is required"),
			};
		}

		if (!permissions || permissions.length === 0) {
			return {
				success: false,
				error: makeError("VC_INVALID_INPUT", "At least one permission is required"),
			};
		}

		const subject: CredentialSubject = {
			id: agentId,
			agentId,
			permissions,
		};

		const credential = buildCredential([KAVACH_PERMISSION_CREDENTIAL], subject, ttl);
		return signCredential(credential, agentId, ttl, format);
	}

	async function issueDelegationCredential(
		input: IssueDelegationCredentialInput,
	): Promise<Result<{ credential: VerifiableCredential; jwt?: string }>> {
		const { agentId, chain, delegationScope, ttl = defaultTtl, format = "jwt" } = input;

		if (!agentId) {
			return {
				success: false,
				error: makeError("VC_INVALID_INPUT", "agentId is required"),
			};
		}

		if (!chain || chain.length === 0) {
			return {
				success: false,
				error: makeError("VC_INVALID_INPUT", "Delegation chain must have at least one link"),
			};
		}

		const subject: CredentialSubject = {
			id: agentId,
			agentId,
			delegationChain: chain,
			...(delegationScope !== undefined ? { delegationScope } : {}),
		};

		const credential = buildCredential([KAVACH_DELEGATION_CREDENTIAL], subject, ttl);
		return signCredential(credential, agentId, ttl, format);
	}

	return {
		issueAgentCredential,
		issuePermissionCredential,
		issueDelegationCredential,
		issuerDid,
	};
}
