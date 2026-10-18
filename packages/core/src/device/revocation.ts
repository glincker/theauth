import type { JWK, JWTVerifyGetKey } from "jose";
import { createLocalJWKSet, importJWK, jwtVerify, SignJWT } from "jose";
import { fromBase64Url, generateId, sha256Raw, toBase64Url } from "../crypto/web-crypto.js";
import type { DeviceConfig } from "./types.js";

/** `typ` header of a signed revocation snapshot. */
export const DEVICE_REVOCATIONS_TYP = "device-revocations+jwt";
/** The only digest format so far: SHA-256 of the UTF-8 device id, first 8 bytes. */
export const REVOCATION_DIGEST = "sha256-64";
const DIGEST_BYTES = 8;
const SKEW_SECONDS = 30;
/** Same one day cap as policy bundles. */
export const MAX_REVOCATION_TTL_SECONDS = 86_400;
/** Largest snapshot the server will sign, so one request cannot read an unbounded table. */
export const DEFAULT_REVOCATION_MAX_ENTRIES = 50_000;

type Signing = NonNullable<DeviceConfig["bundleSigning"]>;

/**
 * Claims of a revocation snapshot. `ids` is the concatenation, sorted ascending, of the 8 byte
 * digests of every revoked or suspended device id of one owner, base64url encoded. 64 bit digests
 * keep the list at 11 characters per device and make a false match about 2^-64 per pair. A Bloom
 * filter would be smaller still, but its false positives would lock out healthy devices.
 */
export interface RevocationSnapshotClaims {
	iss: string;
	/** Owner the list belongs to. Must equal the `owner` claim of the bundle it travels with. */
	sub: string;
	iat: number;
	nbf: number;
	exp: number;
	jti: string;
	/** Issue time in ms. A device keeps the highest one accepted and refuses a lower one. */
	seq: number;
	/** Entry count, checked against the length of `ids`. */
	n: number;
	/** Digest format, `sha256-64`. */
	h: string;
	ids: string;
}

export interface IssuedRevocationSnapshot {
	token: string;
	claims: RevocationSnapshotClaims;
}

async function digest(deviceId: string): Promise<Uint8Array> {
	return (await sha256Raw(deviceId)).slice(0, DIGEST_BYTES);
}

function compare(a: Uint8Array, b: Uint8Array): number {
	for (let i = 0; i < DIGEST_BYTES; i++) {
		const d = (a[i] ?? 0) - (b[i] ?? 0);
		if (d !== 0) return d;
	}
	return 0;
}

export interface SignRevocationInput {
	signing: Signing;
	issuer: string;
	ownerId: string;
	deviceIds: string[];
	ttlSeconds: number;
	nowMs?: number;
}

/** Sign a snapshot of the blocked device ids of one owner (compact JWS). */
export async function signRevocationSnapshot(
	input: SignRevocationInput,
): Promise<IssuedRevocationSnapshot> {
	const nowMs = input.nowMs ?? Date.now();
	const iat = Math.floor(nowMs / 1000);
	const digests = await Promise.all([...new Set(input.deviceIds)].map(digest));
	digests.sort(compare);
	const joined = new Uint8Array(digests.length * DIGEST_BYTES);
	digests.forEach((d, i) => {
		joined.set(d, i * DIGEST_BYTES);
	});
	const claims: RevocationSnapshotClaims = {
		iss: input.issuer,
		sub: input.ownerId,
		iat,
		nbf: iat,
		exp: iat + Math.min(input.ttlSeconds, MAX_REVOCATION_TTL_SECONDS),
		jti: generateId(),
		seq: nowMs,
		n: digests.length,
		h: REVOCATION_DIGEST,
		ids: toBase64Url(joined),
	};
	const key = await importJWK(input.signing.privateKey, input.signing.alg);
	const token = await new SignJWT({ ...claims })
		.setProtectedHeader({
			alg: input.signing.alg,
			typ: DEVICE_REVOCATIONS_TYP,
			kid: input.signing.kid,
		})
		.sign(key);
	return { token, claims };
}

export interface VerifyRevocationOptions {
	keys: { keys: JWK[] } | JWTVerifyGetKey;
	issuer?: string;
	/** Owner the snapshot must be for. Pass the `owner` claim of the verified bundle. */
	owner?: string;
	/**
	 * Fail closed when the snapshot was issued more than this many seconds ago, even if it has not expired. Devices that opt in to offline revocation checks set it to the longest stale window they accept.
	 */
	maxAgeSeconds: number;
	/** Highest `seq` accepted before. A lower one is a rollback to a shorter list. */
	lastSeq?: number;
	now?: Date;
}

export type VerifyRevocationResult =
	| {
			ok: true;
			claims: RevocationSnapshotClaims;
			/** True when the device id is on the list. */
			has: (deviceId: string) => Promise<boolean>;
	  }
	| { ok: false; reason: "invalid" | "stale" | "rollback"; message: string };

/**
 * Check a snapshot: signature, typ, iss, nbf and exp with 30 s skew, age against `maxAgeSeconds`, owner, a well formed sorted list whose length matches `n`, and `seq` not lower than the last accepted. Runs anywhere jose runs.
 */
export async function verifyRevocationSnapshot(
	token: string,
	options: VerifyRevocationOptions,
): Promise<VerifyRevocationResult> {
	const getKey =
		typeof options.keys === "function" ? options.keys : createLocalJWKSet(options.keys);
	const now = options.now ?? new Date();
	const invalid = (message: string): VerifyRevocationResult => ({
		ok: false,
		reason: "invalid",
		message,
	});
	let p: Record<string, unknown>;
	try {
		const v = await jwtVerify(token, getKey, {
			typ: DEVICE_REVOCATIONS_TYP,
			algorithms: ["ES256", "EdDSA"],
			issuer: options.issuer ?? "theauth",
			clockTolerance: SKEW_SECONDS,
			currentDate: now,
		});
		p = v.payload as Record<string, unknown>;
		if (typeof p.exp !== "number" || typeof v.protectedHeader.kid !== "string") {
			throw new Error("no exp or kid");
		}
	} catch (err) {
		const expired = (err as { code?: string }).code === "ERR_JWT_EXPIRED";
		return expired
			? { ok: false, reason: "stale", message: "Revocation snapshot has expired" }
			: invalid("Revocation snapshot signature, issuer or lifetime is invalid");
	}
	if (
		typeof p.sub !== "string" ||
		typeof p.iat !== "number" ||
		typeof p.seq !== "number" ||
		typeof p.n !== "number" ||
		typeof p.ids !== "string" ||
		p.h !== REVOCATION_DIGEST
	) {
		return invalid("Revocation snapshot is missing fields");
	}
	if (options.owner !== undefined && p.sub !== options.owner) {
		return invalid("Revocation snapshot is for another owner");
	}
	if (now.getTime() / 1000 - p.iat > options.maxAgeSeconds) {
		return { ok: false, reason: "stale", message: "Revocation snapshot is older than allowed" };
	}
	if (options.lastSeq !== undefined && p.seq < options.lastSeq) {
		return { ok: false, reason: "rollback", message: "Snapshot is older than the last accepted" };
	}
	let list: Uint8Array;
	try {
		list = fromBase64Url(p.ids);
	} catch {
		return invalid("Revocation list is not base64url");
	}
	if (list.length % DIGEST_BYTES !== 0 || list.length / DIGEST_BYTES !== p.n) {
		return invalid("Revocation list length does not match its count");
	}
	for (let i = 1; i < p.n; i++) {
		const prev = list.subarray((i - 1) * DIGEST_BYTES, i * DIGEST_BYTES);
		if (compare(prev, list.subarray(i * DIGEST_BYTES, (i + 1) * DIGEST_BYTES)) >= 0) {
			return invalid("Revocation list is not sorted");
		}
	}
	const claims = p as unknown as RevocationSnapshotClaims;
	const has = async (deviceId: string): Promise<boolean> => {
		const target = await digest(deviceId);
		let lo = 0;
		let hi = claims.n - 1;
		while (lo <= hi) {
			const mid = (lo + hi) >> 1;
			const c = compare(list.subarray(mid * DIGEST_BYTES, (mid + 1) * DIGEST_BYTES), target);
			if (c === 0) return true;
			if (c < 0) lo = mid + 1;
			else hi = mid - 1;
		}
		return false;
	};
	return { ok: true, claims, has };
}
