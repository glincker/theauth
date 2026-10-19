import type { JWK } from "jose";
import {
	calculateJwkThumbprint,
	decodeJwt,
	decodeProtectedHeader,
	importJWK,
	jwtVerify,
} from "jose";
import {
	constantTimeEqual,
	randomBytes,
	sha256,
	sha256Raw,
	toBase64Url,
} from "../crypto/web-crypto.js";
import type { SecondaryStorage } from "../storage/types.js";
import type { DeviceKeyAlg } from "./types.js";

/** Prefix of device pre shared keys, so secret scanners and logs can tell them apart. */
export const DEVICE_PSK_PREFIX = "tdk_";
/** `typ` header of a device assertion JWT. */
export const DEVICE_ASSERTION_TYP = "device-assertion+jwt";
export const DEVICE_KEY_ALGS: readonly DeviceKeyAlg[] = ["ES256", "ES384", "EdDSA"];

/** Longest lifetime (exp minus iat) of an assertion, same window as DPoP proofs (RFC 9449 section 11.1). */
export const ASSERTION_MAX_LIFETIME_SECONDS = 300;
const SKEW_SECONDS = 30;
const LOOKUP_LENGTH = DEVICE_PSK_PREFIX.length + 12;
const PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] as const;

export function isDevicePsk(value: string): boolean {
	return value.startsWith(DEVICE_PSK_PREFIX) && value.length === DEVICE_PSK_PREFIX.length + 43;
}

/** New pre shared key. Only `hash` and `lookup` are stored. */
export async function generateDevicePsk(): Promise<{
	secret: string;
	hash: string;
	lookup: string;
}> {
	const secret = `${DEVICE_PSK_PREFIX}${toBase64Url(randomBytes(32))}`;
	return { secret, hash: await sha256(secret), lookup: pskLookup(secret) };
}

export function pskLookup(secret: string): string {
	return secret.slice(0, LOOKUP_LENGTH);
}

/** Constant time check of a presented secret against the stored SHA-256 hex. */
export async function pskMatches(secret: string, storedHash: string): Promise<boolean> {
	const actual = new TextEncoder().encode(await sha256(secret));
	return constantTimeEqual(actual, new TextEncoder().encode(storedHash));
}

/**
 * Accept only a public EC or OKP key a device can sign assertions with. Returns the cleaned key (public members only) and its RFC 7638 SHA-256 thumbprint.
 */
export async function normalizeDeviceJwk(
	jwk: JWK,
): Promise<{ ok: true; jwk: JWK; thumbprint: string } | { ok: false; message: string }> {
	if (typeof jwk !== "object" || jwk === null)
		return { ok: false, message: "jwk must be an object" };
	for (const member of PRIVATE_JWK_MEMBERS) {
		if (member in jwk) return { ok: false, message: "jwk must be a public key" };
	}
	let clean: JWK;
	if (jwk.kty === "EC" && (jwk.crv === "P-256" || jwk.crv === "P-384")) {
		if (typeof jwk.x !== "string" || typeof jwk.y !== "string") {
			return { ok: false, message: "EC jwk needs x and y" };
		}
		clean = { kty: "EC", crv: jwk.crv, x: jwk.x, y: jwk.y };
	} else if (jwk.kty === "OKP" && jwk.crv === "Ed25519") {
		if (typeof jwk.x !== "string") return { ok: false, message: "OKP jwk needs x" };
		clean = { kty: "OKP", crv: "Ed25519", x: jwk.x };
	} else {
		return { ok: false, message: "jwk must be EC P-256, EC P-384 or OKP Ed25519" };
	}
	try {
		await importJWK(clean, algOfJwk(clean));
	} catch {
		return { ok: false, message: "jwk is not a valid public key" };
	}
	return { ok: true, jwk: clean, thumbprint: await calculateJwkThumbprint(clean, "sha256") };
}

/** The one algorithm a key may be used with, so an assertion cannot pick a weaker one. */
export function algOfJwk(jwk: JWK): DeviceKeyAlg {
	if (jwk.kty === "OKP") return "EdDSA";
	return jwk.crv === "P-384" ? "ES384" : "ES256";
}

/** `x5t#S256` is base64url SHA-256 of the DER certificate: 43 characters without padding (RFC 8705 section 3.1). */
export function normalizeX509Thumbprint(value: string): string | null {
	const trimmed = value.trim().replace(/=+$/, "");
	return /^[A-Za-z0-9_-]{43}$/.test(trimmed) ? trimmed : null;
}

/** Compute `x5t#S256` from a DER certificate, for hosts that hold the raw certificate. */
export async function x509Thumbprint(der: Uint8Array): Promise<string> {
	return toBase64Url(await sha256Raw(der));
}

/** Read `kid` and `iss` without verifying, to find the credential. */
export function peekAssertion(jwt: string): { kid: string; iss: string } | null {
	try {
		const header = decodeProtectedHeader(jwt);
		const payload = decodeJwt(jwt);
		if (header.typ !== DEVICE_ASSERTION_TYP) return null;
		if (typeof header.kid !== "string" || typeof payload.iss !== "string") return null;
		return { kid: header.kid, iss: payload.iss };
	} catch {
		return null;
	}
}

export interface VerifyAssertionInput {
	jwt: string;
	deviceId: string;
	publicJwk: JWK;
	audience: string;
	storage: SecondaryStorage;
	now?: number;
}

export type AssertionCheck =
	| { ok: true; jti: string }
	| { ok: false; code: "assertion_invalid" | "assertion_replayed"; message: string };

/**
 * Verify a device assertion (RFC 7523 section 3 layout, RFC 9449 replay rules). Order: typ, alg pinned to the key, signature, iss and sub, aud, lifetime, iat, exp, then the jti is recorded. A rejected assertion never consumes its jti.
 */
export async function verifyDeviceAssertion(input: VerifyAssertionInput): Promise<AssertionCheck> {
	const invalid = (message: string): AssertionCheck => ({
		ok: false,
		code: "assertion_invalid",
		message,
	});
	const alg = algOfJwk(input.publicJwk);
	let payload: Record<string, unknown>;
	try {
		const key = await importJWK(input.publicJwk, alg);
		const verified = await jwtVerify(input.jwt, key, {
			algorithms: [alg],
			typ: DEVICE_ASSERTION_TYP,
			clockTolerance: SKEW_SECONDS,
			currentDate: input.now === undefined ? undefined : new Date(input.now * 1000),
		});
		payload = verified.payload as Record<string, unknown>;
	} catch {
		return invalid("Device assertion signature or time claims are invalid");
	}
	if (payload.iss !== input.deviceId || payload.sub !== input.deviceId) {
		return invalid("Device assertion iss and sub must be the device id");
	}
	const aud = payload.aud;
	const audOk = Array.isArray(aud) ? aud.includes(input.audience) : aud === input.audience;
	if (!audOk) return invalid("Device assertion aud does not match");
	const { iat, exp, jti } = payload;
	if (typeof iat !== "number" || typeof exp !== "number") {
		return invalid("Device assertion needs iat and exp");
	}
	if (exp - iat > ASSERTION_MAX_LIFETIME_SECONDS || exp <= iat) {
		return invalid(`Device assertion lifetime must be at most ${ASSERTION_MAX_LIFETIME_SECONDS}s`);
	}
	const now = input.now ?? Math.floor(Date.now() / 1000);
	if (iat > now + SKEW_SECONDS) return invalid("Device assertion iat is in the future");
	if (typeof jti !== "string" || jti.length < 16 || jti.length > 256) {
		return invalid("Device assertion jti must be 16 to 256 characters");
	}
	// Single use. incr is atomic on stores that report atomicIncr.
	const ttl = Math.max(1, exp - now + SKEW_SECONDS + 60);
	const key = `jti:${await sha256(`${input.deviceId}\n${jti}`)}`;
	const seen = await input.storage.incr(key, ttl);
	if (seen.count > 1) {
		return { ok: false, code: "assertion_replayed", message: "Device assertion was already used" };
	}
	return { ok: true, jti };
}
