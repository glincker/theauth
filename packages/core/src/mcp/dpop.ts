import type { JWK } from "jose";
import { calculateJwkThumbprint, decodeProtectedHeader, importJWK, jwtVerify } from "jose";
import { sha256Raw, toBase64Url } from "../crypto/web-crypto.js";
import { memoryStorage } from "../storage/memory.js";
import type { SecondaryStorage } from "../storage/types.js";
import type { DpopAlg } from "./dpop-types.js";
import type { McpAuthContext, Result } from "./types.js";
import { generateSecureToken, timingSafeEqual } from "./utils.js";

export const DEFAULT_DPOP_ALGS: DpopAlg[] = ["ES256", "ES384", "EdDSA", "PS256"];

const DEFAULT_MAX_AGE = 300;
const DEFAULT_SKEW = 30;
const DEFAULT_NONCE_TTL = 300;
const MAX_NONCE_LENGTH = 128;
/** Members that only exist on private or symmetric JWKs. */
const PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] as const;

const fallbackStorage = new WeakMap<object, SecondaryStorage>();

/** Storage for the replay cache and nonces: configured, else per-context memory. */
export function getDpopStorage(ctx: McpAuthContext): SecondaryStorage {
	const configured = ctx.config.dpop?.storage;
	if (configured) return configured;
	let store = fallbackStorage.get(ctx);
	if (!store) {
		store = memoryStorage();
		fallbackStorage.set(ctx, store);
	}
	return store;
}

/** Algorithms advertised in metadata and challenges. */
export function getDpopAlgs(ctx: McpAuthContext): DpopAlg[] {
	return ctx.config.dpop?.algs ?? DEFAULT_DPOP_ALGS;
}

/** Base64url SHA-256 of an access token, the value of the `ath` claim. */
export async function computeAth(accessToken: string): Promise<string> {
	return toBase64Url(await sha256Raw(accessToken));
}

/**
 * Normalize an `htu` for comparison: scheme, host and path only. Query and
 * fragment are dropped as RFC 9449 section 4.3 requires.
 */
export function normalizeHtu(value: string): string | null {
	try {
		const url = new URL(value);
		return `${url.origin}${url.pathname}`;
	} catch {
		return null;
	}
}

// ─── Nonces ──────────────────────────────────────────────────────────────────

const NONCE_CURRENT = "dpop:nonce:current";

/**
 * The nonce to hand out now. One nonce is current at a time and rotates when
 * it expires; a retired nonce is still accepted for one more lifetime so a
 * client mid-request is not bounced twice.
 */
export async function getCurrentDpopNonce(ctx: McpAuthContext): Promise<string> {
	const storage = getDpopStorage(ctx);
	const ttl = ctx.config.dpop?.nonceTtlSeconds ?? DEFAULT_NONCE_TTL;
	const current = await storage.get(NONCE_CURRENT);
	if (current) return current;
	const nonce = generateSecureToken(24);
	await storage.set(`dpop:nonce:v:${nonce}`, "1", ttl * 2);
	await storage.set(NONCE_CURRENT, nonce, ttl);
	return nonce;
}

async function isValidNonce(ctx: McpAuthContext, nonce: unknown): Promise<boolean> {
	if (typeof nonce !== "string" || nonce.length === 0 || nonce.length > MAX_NONCE_LENGTH) {
		return false;
	}
	return (await getDpopStorage(ctx).get(`dpop:nonce:v:${nonce}`)) !== null;
}

// ─── Proof verification ──────────────────────────────────────────────────────

export interface VerifyDpopProofInput {
	/** The `DPoP` header value. */
	proof: string;
	/** HTTP method of the request the proof is attached to. */
	method: string;
	/** Full URL of that request. Query and fragment are ignored. */
	url: string;
	/** When set, the proof must carry a matching `ath` (resource requests). */
	accessToken?: string;
	/** Demand a valid server nonce. */
	requireNonce?: boolean;
}

export interface VerifiedDpopProof {
	/** RFC 7638 SHA-256 thumbprint of the proof key. */
	jkt: string;
	jti: string;
	iat: number;
}

function fail(message: string, details?: Record<string, unknown>): Result<VerifiedDpopProof> {
	return {
		success: false,
		error: { code: "INVALID_DPOP_PROOF", message, ...(details ? { details } : {}) },
	};
}

/**
 * Verify a DPoP proof JWT (RFC 9449 section 4.3).
 *
 * Checks, in order: header (`typ`, `alg`, public `jwk`), signature, `htm`,
 * `htu`, `iat` window (any `exp`/`nbf` is also honored), `ath`, nonce, then records the `jti`. The replay cache
 * is written last so a rejected proof never consumes a `jti`, which keeps a
 * `use_dpop_nonce` retry possible with a fresh proof.
 */
export async function verifyDpopProof(
	ctx: McpAuthContext,
	input: VerifyDpopProofInput,
): Promise<Result<VerifiedDpopProof>> {
	const dpop = ctx.config.dpop;
	if (!dpop) return fail("DPoP is not enabled");

	let header: ReturnType<typeof decodeProtectedHeader>;
	try {
		header = decodeProtectedHeader(input.proof);
	} catch {
		return fail("DPoP proof is not a valid JWT");
	}
	if (header.typ !== "dpop+jwt") return fail('DPoP proof header typ must be "dpop+jwt"');
	const allowed = getDpopAlgs(ctx);
	if (typeof header.alg !== "string" || !(allowed as string[]).includes(header.alg)) {
		return fail("DPoP proof algorithm is not supported", { algs: allowed });
	}
	const jwk = header.jwk as JWK | undefined;
	if (!jwk || typeof jwk !== "object") return fail("DPoP proof header is missing jwk");
	for (const member of PRIVATE_JWK_MEMBERS) {
		if (member in jwk) return fail("DPoP proof jwk must be a public key");
	}

	let payload: Record<string, unknown>;
	try {
		const key = await importJWK(jwk, header.alg);
		const verified = await jwtVerify(input.proof, key, {
			algorithms: [header.alg],
			typ: "dpop+jwt",
		});
		payload = verified.payload as Record<string, unknown>;
	} catch {
		return fail("DPoP proof signature is invalid");
	}

	if (typeof payload.jti !== "string" || payload.jti.length === 0) {
		return fail("DPoP proof is missing jti");
	}
	if (payload.htm !== input.method.toUpperCase()) {
		return fail("DPoP proof htm does not match the request method");
	}
	const expectedHtu = normalizeHtu(input.url);
	const proofHtu = typeof payload.htu === "string" ? normalizeHtu(payload.htu) : null;
	if (!expectedHtu || !proofHtu || proofHtu !== expectedHtu) {
		return fail("DPoP proof htu does not match the request URL");
	}

	const maxAge = dpop.proofMaxAgeSeconds ?? DEFAULT_MAX_AGE;
	const skew = dpop.clockSkewSeconds ?? DEFAULT_SKEW;
	const iat = payload.iat;
	if (typeof iat !== "number" || !Number.isFinite(iat)) return fail("DPoP proof is missing iat");
	const now = Math.floor(Date.now() / 1000);
	if (iat > now + skew) return fail("DPoP proof iat is in the future");
	if (iat < now - maxAge - skew) return fail("DPoP proof has expired");

	if (input.accessToken !== undefined) {
		if (typeof payload.ath !== "string") return fail("DPoP proof is missing ath");
		const expectedAth = await computeAth(input.accessToken);
		if (!timingSafeEqual(payload.ath, expectedAth)) {
			return fail("DPoP proof ath does not match the access token");
		}
	}

	if (input.requireNonce ?? dpop.requireNonce === true) {
		if (!(await isValidNonce(ctx, payload.nonce))) {
			const nonce = await getCurrentDpopNonce(ctx);
			return {
				success: false,
				error: {
					code: "USE_DPOP_NONCE",
					message: "A server-provided DPoP nonce is required",
					details: { dpopNonce: nonce },
				},
			};
		}
	}

	const jkt = await calculateJwkThumbprint(jwk, "sha256");

	// Replay cache. incr() is atomic on stores that report atomicIncr, so two
	// concurrent submissions of one proof cannot both see count 1.
	const ttl = maxAge + 2 * skew + 1;
	const id = toBase64Url(await sha256Raw(`${jkt}\n${payload.jti}`));
	const seen = await getDpopStorage(ctx).incr(`dpop:jti:${id}`, ttl);
	if (seen.count > 1) return fail("DPoP proof has already been used");

	return { success: true, data: { jkt, jti: payload.jti, iat } };
}

/** Read the single `DPoP` header. Several values (comma-joined by fetch) are invalid. */
export function readDpopHeader(request: Request): string | null {
	const value = request.headers.get("dpop");
	if (value === null) return null;
	return value.includes(",") ? "" : value.trim();
}
