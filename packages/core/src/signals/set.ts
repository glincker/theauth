/**
 * Security Event Token (RFC 8417) signing and verification.
 *
 * A SET is a signed JWT with header `typ: secevent+jwt`, no `exp`, and an
 * `events` claim keyed by event type URI.
 */

import type { JWK, JWTVerifyGetKey } from "jose";
import { importJWK, jwtVerify, SignJWT } from "jose";
import { generateId } from "../crypto/web-crypto.js";
import { parseSubject } from "./subjects.js";
import type { EventPayload, Result, SecurityEventToken, SubjectIdentifier } from "./types.js";
import { SET_JWT_TYP } from "./types.js";

export type SigningKey = CryptoKey | Uint8Array | JWK;
export type VerifyKey = CryptoKey | Uint8Array | JWTVerifyGetKey;

export const DEFAULT_SET_ALGORITHMS = ["RS256", "ES256", "EdDSA"];

export interface SignSetParams {
	issuer: string;
	audience: string | string[];
	events: Record<string, EventPayload>;
	signingKey: SigningKey;
	alg: string;
	kid?: string;
	subId?: SubjectIdentifier;
	/** Defaults to a fresh random id. */
	jti?: string;
	/** Seconds since epoch. Defaults to now. */
	iat?: number;
	txn?: string;
}

async function resolveKey(key: SigningKey, alg: string): Promise<CryptoKey | Uint8Array> {
	if (key instanceof Uint8Array) return key;
	if (typeof CryptoKey !== "undefined" && key instanceof CryptoKey) return key;
	const imported = await importJWK(key as JWK, alg);
	return imported as CryptoKey | Uint8Array;
}

/** Sign a SET. Throws when `events` is empty or the key does not fit `alg`. */
export async function signSet(params: SignSetParams): Promise<string> {
	if (Object.keys(params.events).length === 0) {
		throw new Error("A SET needs at least one event.");
	}
	const key = await resolveKey(params.signingKey, params.alg);
	const iat = params.iat ?? Math.floor(Date.now() / 1000);
	const claims: Record<string, unknown> = { events: params.events };
	if (params.subId) claims.sub_id = params.subId;
	if (params.txn) claims.txn = params.txn;
	return new SignJWT(claims)
		.setProtectedHeader({
			alg: params.alg,
			typ: SET_JWT_TYP,
			...(params.kid ? { kid: params.kid } : {}),
		})
		.setIssuer(params.issuer)
		.setAudience(params.audience)
		.setIssuedAt(iat)
		.setJti(params.jti ?? generateId())
		.sign(key);
}

export interface VerifySetOptions {
	issuer: string;
	/** Expected audience; the SET must name it. */
	audience: string;
	key: VerifyKey;
	algorithms?: string[];
	/** Reject SETs older than this many seconds. Off by default (poll can lag). */
	maxAgeSeconds?: number;
	clockToleranceSeconds?: number;
}

function bad<T>(code: string, message: string): Result<T> {
	return { ok: false, code, message };
}

function typOk(typ: unknown): boolean {
	if (typeof typ !== "string") return false;
	const t = typ.toLowerCase();
	return t === SET_JWT_TYP || t === `application/${SET_JWT_TYP}`;
}

/**
 * Verify signature, issuer, audience and shape. Error codes follow the
 * RFC 8935 `err` values (`invalid_key`, `invalid_issuer`, `invalid_audience`,
 * `invalid_request`).
 */
export async function verifySet(
	token: string,
	options: VerifySetOptions,
): Promise<Result<SecurityEventToken>> {
	const getKey: JWTVerifyGetKey =
		typeof options.key === "function" ? options.key : async () => options.key as CryptoKey;
	let verified: Awaited<ReturnType<typeof jwtVerify>>;
	try {
		verified = await jwtVerify(token, getKey, {
			issuer: options.issuer,
			audience: options.audience,
			algorithms: options.algorithms ?? DEFAULT_SET_ALGORITHMS,
			...(options.maxAgeSeconds !== undefined ? { maxTokenAge: `${options.maxAgeSeconds}s` } : {}),
			clockTolerance: options.clockToleranceSeconds ?? 30,
			requiredClaims: ["iss", "iat", "jti", "aud", "events"],
		});
	} catch (err) {
		const name = err instanceof Error ? err.name : "";
		const message = err instanceof Error ? err.message : "SET verification failed";
		if (name === "JWTClaimValidationFailed") {
			const claim = (err as { claim?: string }).claim;
			if (claim === "iss") return bad("invalid_issuer", message);
			if (claim === "aud") return bad("invalid_audience", message);
			return bad("invalid_request", message);
		}
		if (name === "JWSSignatureVerificationFailed" || name === "JWKSNoMatchingKey") {
			return bad("invalid_key", message);
		}
		return bad("invalid_request", message);
	}
	if (!typOk(verified.protectedHeader.typ)) {
		return bad("invalid_request", `typ must be ${SET_JWT_TYP}`);
	}
	const payload = verified.payload;
	if ("exp" in payload) return bad("invalid_request", "a SET must not carry exp");
	const events = payload.events;
	if (typeof events !== "object" || events === null || Array.isArray(events)) {
		return bad("invalid_request", "events must be an object");
	}
	const entries = Object.entries(events as Record<string, unknown>);
	if (entries.length === 0) return bad("invalid_request", "events is empty");
	const checked = new Map<string, EventPayload>();
	for (const [uri, value] of entries) {
		if (typeof value !== "object" || value === null || Array.isArray(value)) {
			return bad("invalid_request", "event payload must be an object");
		}
		checked.set(uri, value as EventPayload);
	}
	let subId: SubjectIdentifier | undefined;
	if (payload.sub_id !== undefined) {
		const parsed = parseSubject(payload.sub_id);
		if (!parsed) return bad("invalid_request", "sub_id is not a valid subject identifier");
		subId = parsed;
	}
	const token0: SecurityEventToken = {
		iss: payload.iss as string,
		iat: payload.iat as number,
		jti: payload.jti as string,
		aud: payload.aud as string | string[],
		events: Object.fromEntries(checked),
		...(subId ? { sub_id: subId } : {}),
		...(typeof payload.txn === "string" ? { txn: payload.txn } : {}),
		...(typeof payload.toe === "number" ? { toe: payload.toe } : {}),
	};
	return { ok: true, value: token0 };
}
