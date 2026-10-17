/** Exports audit records as W3C Verifiable Credentials. */

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

export const THEAUTH_AUDIT_CREDENTIAL = "TheAuthAuditCredential";

/** Context URL for TheAuthAuditCredential. Defined locally; the URL does not need to resolve. */
export const THEAUTH_AUDIT_CONTEXT = "https://theauth.dev/contexts/audit/v1.jsonld";

const THEAUTH_VERSION = "0.3.0";
const DEFAULT_TTL_SECONDS = 86400;

/** AuditRecord is an alias for AuditEntry used in the VC export surface. */
export type AuditRecord = AuditEntry;

export interface ExportAuditOptions {
	since: Date;
	until: Date;
	/** DID of the issuer. Must match the keypair in `issuerConfig`. */
	issuerDid: string;
	issuerConfig: VCIssuerConfig;
	/** Output format. Default: `"ldp_vc"` (JSON-LD with embedded proof). */
	format?: "ldp_vc" | "jwt_vc";
	/** Output structure. Default: `"individual"` (one VC per record). */
	output?: "individual" | "presentation";
	filter?: (record: AuditRecord) => boolean;
	records: AuditRecord[];
}

export interface AuditExportResult {
	/** Individual credentials, one per audit record. With `output: "presentation"` they are wrapped in one presentation. */
	credentials: VerifiableCredential[];
	/** JWT strings when `format` is `jwt_vc`, parallel to `credentials`. */
	jwts?: string[];
	presentation?: VerifiablePresentation;
	format: "ldp_vc" | "jwt_vc";
	issuedAt: Date;
	count: number;
}

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

function toDecision(result: AuditEntry["result"]): "allow" | "deny" | "approval_required" {
	if (result === "allowed") return "allow";
	if (result === "escalated") return "approval_required";
	// "denied" and "rate_limited" both map to deny in the VC decision field
	return "deny";
}

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

async function signAsJsonLd(
	credential: VerifiableCredential,
	config: VCIssuerConfig,
): Promise<VerifiableCredential> {
	const { issuerDid, privateKeyJwk } = config;
	const kid = `${issuerDid}#${issuerDid.split(":").pop() ?? "key-1"}`;
	const key = await importJWK(privateKeyJwk, "EdDSA");

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

/** Exports the given audit records within the time range as Verifiable Credentials. */
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

	const inRange = records.filter((r) => {
		const t = r.timestamp.getTime();
		return t >= since.getTime() && t <= until.getTime();
	});

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

/** Filters audit records by time range, with an optional predicate. */
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
