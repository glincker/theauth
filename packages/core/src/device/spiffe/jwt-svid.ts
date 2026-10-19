import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify } from "jose";
import type { SpiffeBundleStore } from "./bundle-store.js";
import { parseSpiffeId } from "./spiffe-id.js";
import type { SvidFailure } from "./x509-svid.js";

/**
 * JWT-SVID validation per the SPIFFE JWT-SVID specification
 * (https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md):
 *  - section 2.1: `alg` is one of RS256/384/512, ES256/384/512, PS256/384/512, checked before anything else
 *  - section 2.3: `typ`, when set, is JWT or JOSE; section 2: no other header than alg, kid, typ
 *  - section 3.1 to 3.3: `sub` is a SPIFFE ID, `aud` is required and must contain our audience, `exp` is required
 *  - section 4: signature verified with a `jwt-svid` key of the trust domain named by `sub`
 * Beyond the spec: `kid` is required to pick the key, and `exp` may be at most `maxTtlSeconds` ahead
 * (default 3600) so a long lived token is refused. A JWT-SVID has no proof of possession, so it is a
 * bearer credential: keep it to TLS and use one audience per service (section 7.2).
 */
const ALGS = [
	"RS256",
	"RS384",
	"RS512",
	"ES256",
	"ES384",
	"ES512",
	"PS256",
	"PS384",
	"PS512",
] as const;
type SvidAlg = (typeof ALGS)[number];
const ALLOWED_HEADERS = new Set(["alg", "kid", "typ"]);

export interface JwtSvidOptions {
	/** Audience values this service accepts. At least one. The token's `aud` must contain one of them. */
	audience: string[];
	now: Date;
	/** Default 30. */
	clockSkewSeconds?: number;
	/** Largest accepted time from now to `exp`, and from `iat` to `exp` when `iat` is set. Default 3600. */
	maxTtlSeconds?: number;
}

export interface JwtSvidIdentity {
	spiffeId: string;
	trustDomain: string;
	path: string;
	audience: string[];
	expiresAt: Date;
	kid: string;
}

export type JwtSvidResult =
	| { ok: true; identity: JwtSvidIdentity }
	| { ok: false; code: SvidFailure; reason: string };

const fail = (code: SvidFailure, reason: string): JwtSvidResult => ({ ok: false, code, reason });

export async function verifyJwtSvid(
	token: string,
	bundles: Pick<SpiffeBundleStore, "get">,
	options: JwtSvidOptions,
): Promise<JwtSvidResult> {
	if (options.audience.length === 0) return fail("wrong_audience", "No audience configured");
	if (token.length > 16_384 || token.split(".").length !== 3)
		return fail("malformed", "Not a compact JWS");
	let header: ReturnType<typeof decodeProtectedHeader>;
	let claims: ReturnType<typeof decodeJwt>;
	try {
		header = decodeProtectedHeader(token);
		claims = decodeJwt(token);
	} catch {
		return fail("malformed", "Token could not be decoded");
	}
	const alg = header.alg as SvidAlg | undefined;
	if (!alg || !ALGS.includes(alg))
		return fail("unsupported_alg", "Algorithm is not allowed for a JWT-SVID");
	if (Object.keys(header).some((k) => !ALLOWED_HEADERS.has(k))) {
		return fail("malformed", "Token has a header JWT-SVID does not allow");
	}
	if (header.typ !== undefined && header.typ !== "JWT" && header.typ !== "JOSE") {
		return fail("malformed", "typ must be JWT or JOSE");
	}
	if (typeof header.kid !== "string" || header.kid === "")
		return fail("malformed", "Token has no kid");
	if (typeof claims.sub !== "string") return fail("missing_claim", "Token has no sub");
	if (claims.aud === undefined) return fail("missing_claim", "Token has no aud");
	if (claims.exp === undefined) return fail("missing_claim", "Token has no exp");
	const id = parseSpiffeId(claims.sub);
	if (!id.ok) return fail("invalid_spiffe_id", id.reason);
	if (id.path === "") return fail("invalid_spiffe_id", "Workload SPIFFE ID needs a path");
	const bundle = await bundles.get(id.trustDomain);
	if (!bundle) return fail("untrusted_domain", "No trust bundle for this trust domain");
	const jwk = bundle.jwtAuthorities.get(header.kid);
	if (!jwk) return fail("untrusted_chain", "No jwt-svid key with this kid");
	try {
		const key = await importJWK({ ...jwk, alg }, alg);
		const skew = options.clockSkewSeconds ?? 30;
		const { payload } = await jwtVerify(token, key, {
			algorithms: [alg],
			audience: options.audience,
			currentDate: options.now,
			clockTolerance: skew,
			requiredClaims: ["sub", "aud", "exp"],
		});
		const exp = payload.exp as number;
		const maxTtl = options.maxTtlSeconds ?? 3600;
		const nowSec = Math.floor(options.now.getTime() / 1000);
		if (
			exp - nowSec > maxTtl + skew ||
			(payload.iat !== undefined && exp - payload.iat > maxTtl + skew)
		) {
			return fail("lifetime_too_long", "JWT-SVID expires too far in the future");
		}
		return {
			ok: true,
			identity: {
				spiffeId: id.id,
				trustDomain: id.trustDomain,
				path: id.path,
				audience: Array.isArray(payload.aud) ? payload.aud : [payload.aud as string],
				expiresAt: new Date(exp * 1000),
				kid: header.kid,
			},
		};
	} catch (err) {
		const code = (err as { code?: string }).code;
		if (code === "ERR_JWT_EXPIRED") return fail("expired", "JWT-SVID has expired");
		if (code === "ERR_JWT_CLAIM_VALIDATION_FAILED") {
			const claim = (err as { claim?: string }).claim;
			if (claim === "aud") return fail("wrong_audience", "Audience does not match");
			if (claim === "nbf") return fail("not_yet_valid", "JWT-SVID is not valid yet");
			return fail("missing_claim", "A required claim is invalid");
		}
		return fail("bad_signature", "JWT-SVID signature is invalid");
	}
}
