/**
 * Export audit records as W3C Verifiable Credentials.
 *
 * Takes a time range of audit log entries and returns either individual
 * credentials per record or a single Verifiable Presentation wrapping
 * all of them. Useful for compliance exports that must be
 * cryptographically verifiable (EU AI Act Article 12, SOC 2 CC7).
 *
 * Context URL: https://theauth.com/contexts/audit/v1.jsonld
 * This context is defined locally — the URL does not need to resolve at
 * runtime. It serves as a stable identifier for the credential schema.
 */

import { CompactSign, importJWK, SignJWT } from "jose";
import { generateId } from "../crypto/web-crypto.js";
import type { AuditEntry } from "../types.js";
import type {
	CredentialSubject,
	Proof,
	VCIssuerConfig,
	VerifiableCredential,
	VerifiablePresentation,
} from "./types.js";
import { VC_CONTEXT_V2, VC_TYPE_CREDENTIAL, VC_TYPE_PRESENTATION } from "./types.js";

// ─── Constants ───────────────────────────────────────────────────────────────

export const THEAUTH_AUDIT_CREDENTIAL = "TheAuthAuditCredential";

/**
 * Context URL for TheAuthAuditCredential.
 * Defined locally — the URL does not need to resolve at runtime.
 */
export const THEAUTH_AUDIT_CONTEXT = "https://theauth.com/contexts/audit/v1.jsonld";

const THEAUTH_VERSION = "0.3.0";
const DEFAULT_TTL_SECONDS = 86400;

// ─── Types ───────────────────────────────────────────────────────────────────

/** AuditRecord is an alias for AuditEntry used in the VC export surface. */
export type AuditRecord = AuditEntry;

/** Options passed to `exportAuditAsVC`. */
export interface ExportAuditOptions {
	/** Start of the time range (inclusive). */
	since: Date;
	/** End of the time range (inclusive). */
	until: Date;
	/**
	 * DID of the issuer signing the credentials.
	 * Must match the keypair in `issuerConfig`.
	 */
	issuerDid: string;
	/** Private/public keypair config for signing. */
	issuerConfig: VCIssuerConfig;
	/** Output format. Default: `"ldp_vc"` (JSON-LD with embedded proof). */
	format?: "ldp_vc" | "jwt_vc";
	/** Output structure. Default: `"individual"` (one VC per record). */
	output?: "individual" | "presentation";
	/** Optional filter applied after the time range query. */
	filter?: (record: AuditRecord) => boolean;
	/** Records to export. Pass the results of `listAuditRecords` or `kavach.audit.query()`. */
	records: AuditRecord[];
}

/** The result of `exportAuditAsVC`. */
export interface AuditExportResult {
	/**
	 * Individual credentials — one per audit record.
	 * When `output === "presentation"`, these are also embedded in `presentation`.
	 */
	credentials: VerifiableCredential[];
	/**
	 * JWT strings when `format === "jwt_vc"`. Parallel to `credentials`.
	 * Pass these to `verifyCredential()` instead of the credential objects.
	 */
	jwts?: string[];
	/** Present only when `output === "presentation"`. */
	presentation?: VerifiablePresentation;
	/** The format used. */
	format: "ldp_vc" | "jwt_vc";
	/** Timestamp of the export run. */
	issuedAt: Date;
	/** Number of credentials produced. */
	count: number;
}

/** The credentialSubject for a TheAuthAuditCredential. */
export interface AuditCredentialSubject {
	id: string;
	agentId: string;
	principalId?: string;
	operation: string;
	target: string;
	decision: "allow" | "deny" | "approval_required";
	policyName?: string;
	timestamp: string;
	traceId?: string;
	theauthVersion: string;
}

// ─── Decision mapping ────────────────────────────────────────────────────────

function toDecision(result: AuditEntry["result"]): "allow" | "deny" | "approval_required" {
	if (result === "allowed") return "allow";
	// "denied" and "rate_limited" both map to deny in the VC decision field
	return "deny";
}

// ─── Credential builder ──────────────────────────────────────────────────────

function buildAuditCredential(record: AuditRecord, issuerDid: string): VerifiableCredential {
	const subject: AuditCredentialSubject = {
		id: record.id,
		agentId: record.agentId,
		...(record.userId ? { principalId: record.userId } : {}),
		operation: record.action,
		target: record.resource,
		decision: toDecision(record.result),
		...(record.reason ? { policyName: record.reason } : {}),
		timestamp: record.timestamp.toISOString(),
		theauthVersion: THEAUTH_VERSION,
	};

	return {
		"@context": [VC_CONTEXT_V2, THEAUTH_AUDIT_CONTEXT],
		id: `urn:uuid:${generateId()}`,
		type: [VC_TYPE_CREDENTIAL, THEAUTH_AUDIT_CREDENTIAL],
		issuer: issuerDid,
		issuanceDate: new Date().toISOString(),
		expirationDate: new Date(Date.now() + DEFAULT_TTL_SECONDS * 1000).toISOString(),
		// Cast: AuditCredentialSubject is intentionally wider than CredentialSubject
		// because the VC schema uses an open-ended subject. The additional fields
		// (operation, target, decision, etc.) are preserved via spread at runtime.
		credentialSubject: subject as unknown as CredentialSubject,
	};
}

// ─── Signing ──────────────────────────────────────────────────────────────────

async function signAsJsonLd(
	credential: VerifiableCredential,
	config: VCIssuerConfig,
): Promise<VerifiableCredential> {
	const { issuerDid, privateKeyJwk } = config;
	const kid = `${issuerDid}#${issuerDid.split(":").pop() ?? "key-1"}`;
	const key = await importJWK(privateKeyJwk, "EdDSA");

	// Sign the credential body (without proof) as a compact JWS
	const { proof: _proof, ...vcWithoutProof } = credential;
	const payload = new TextEncoder().encode(JSON.stringify(vcWithoutProof));

	const jws = await new CompactSign(payload).setProtectedHeader({ alg: "EdDSA", kid }).sign(key);

	const proof: Proof = {
		type: "JsonWebSignature2020",
		created: new Date().toISOString(),
		verificationMethod: kid,
		proofPurpose: "assertionMethod",
		jws,
	};

	return { ...credential, proof };
}

async function signAsJwt(
	credential: VerifiableCredential,
	config: VCIssuerConfig,
): Promise<{ credential: VerifiableCredential; jwt: string }> {
	const { issuerDid, privateKeyJwk } = config;
	const ttl = config.defaultTtl ?? DEFAULT_TTL_SECONDS;
	const kid = `${issuerDid}#${issuerDid.split(":").pop() ?? "key-1"}`;
	const key = await importJWK(privateKeyJwk, "EdDSA");

	const { proof: _proof, ...vcWithoutProof } = credential;

	const builder = new SignJWT({ vc: vcWithoutProof })
		.setProtectedHeader({ alg: "EdDSA", kid, typ: "JWT" })
		.setIssuer(issuerDid)
		.setIssuedAt()
		.setExpirationTime(Math.floor(Date.now() / 1000) + ttl);

	if (credential.id) builder.setJti(credential.id);
	if (credential.credentialSubject.id) builder.setSubject(credential.credentialSubject.id);

	const jwt = await builder.sign(key);
	return { credential, jwt };
}

async function signPresentationAsJsonLd(
	presentation: VerifiablePresentation,
	config: VCIssuerConfig,
): Promise<VerifiablePresentation> {
	const { issuerDid, privateKeyJwk } = config;
	const kid = `${issuerDid}#${issuerDid.split(":").pop() ?? "key-1"}`;
	const key = await importJWK(privateKeyJwk, "EdDSA");

	const { proof: _proof, ...vpWithoutProof } = presentation;
	const payload = new TextEncoder().encode(JSON.stringify(vpWithoutProof));

	const jws = await new CompactSign(payload).setProtectedHeader({ alg: "EdDSA", kid }).sign(key);

	const proof: Proof = {
		type: "JsonWebSignature2020",
		created: new Date().toISOString(),
		verificationMethod: kid,
		proofPurpose: "assertionMethod",
		jws,
	};

	return { ...presentation, proof };
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Export a set of audit records as Verifiable Credentials.
 *
 * Pass `records` from `kavach.audit.query()` or `listAuditRecords`.
 * The function applies the optional `filter`, signs each record with
 * the issuer keypair, and returns either individual VCs or a single
 * Verifiable Presentation.
 *
 * ```ts
 * const result = await exportAuditAsVC({
 *   since: new Date('2025-01-01'),
 *   until: new Date('2025-01-31'),
 *   issuerDid: keyPair.did,
 *   issuerConfig: {
 *     issuerDid: keyPair.did,
 *     privateKeyJwk: keyPair.privateKeyJwk,
 *     publicKeyJwk: keyPair.publicKeyJwk,
 *   },
 *   records,
 * });
 * console.log(result.count); // 42
 * ```
 */
export async function exportAuditAsVC(options: ExportAuditOptions): Promise<AuditExportResult> {
	const {
		since,
		until,
		issuerDid,
		issuerConfig,
		format = "ldp_vc",
		output = "individual",
		filter,
		records,
	} = options;

	// Apply time range filter first
	const inRange = records.filter((r) => {
		const t = r.timestamp.getTime();
		return t >= since.getTime() && t <= until.getTime();
	});

	// Apply caller-supplied filter if provided
	const filtered = filter ? inRange.filter(filter) : inRange;

	if (filtered.length === 0) {
		return {
			credentials: [],
			format,
			issuedAt: new Date(),
			count: 0,
		};
	}

	const credentials: VerifiableCredential[] = [];
	const jwts: string[] = [];

	for (const record of filtered) {
		const base = buildAuditCredential(record, issuerDid);

		if (format === "jwt_vc") {
			const { credential, jwt } = await signAsJwt(base, issuerConfig);
			credentials.push(credential);
			jwts.push(jwt);
		} else {
			const signed = await signAsJsonLd(base, issuerConfig);
			credentials.push(signed);
		}
	}

	const issuedAt = new Date();

	if (output === "individual") {
		return {
			credentials,
			...(format === "jwt_vc" ? { jwts } : {}),
			format,
			issuedAt,
			count: credentials.length,
		};
	}

	// Build a Verifiable Presentation wrapping all credentials
	const basePresentation: VerifiablePresentation = {
		"@context": [VC_CONTEXT_V2, THEAUTH_AUDIT_CONTEXT],
		id: `urn:uuid:${generateId()}`,
		type: [VC_TYPE_PRESENTATION],
		holder: issuerDid,
		verifiableCredential: credentials,
	};

	const presentation =
		format === "jwt_vc"
			? basePresentation
			: await signPresentationAsJsonLd(basePresentation, issuerConfig);

	return {
		credentials,
		...(format === "jwt_vc" ? { jwts } : {}),
		presentation,
		format,
		issuedAt,
		count: credentials.length,
	};
}

/**
 * Filter audit records by time range with an optional predicate.
 *
 * Convenience helper for callers that already have records in memory
 * and want to slice them before passing to `exportAuditAsVC`.
 *
 * ```ts
 * const records = await kavach.audit.query({ since, until });
 * const denyRecords = listAuditRecords(records, since, until, r => r.result === 'denied');
 * ```
 */
export function listAuditRecords(
	records: AuditRecord[],
	since: Date,
	until: Date,
	filter?: (record: AuditRecord) => boolean,
): AuditRecord[] {
	const inRange = records.filter((r) => {
		const t = r.timestamp.getTime();
		return t >= since.getTime() && t <= until.getTime();
	});

	return filter ? inRange.filter(filter) : inRange;
}
