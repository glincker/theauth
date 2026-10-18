import type { JWK, JWTVerifyGetKey } from "jose";
import { createLocalJWKSet, importJWK, jwtVerify, SignJWT } from "jose";
import { generateId } from "../crypto/web-crypto.js";
import type { DecisionCode } from "../permission/codes.js";
import { DECISION_CODES } from "../permission/codes.js";
import { findMatchingPermission, inspectConstraints } from "../policy/abac.js";
import type { Permission } from "../types.js";
import type { DeviceBundleClaims, DeviceConfig, IssuedDeviceBundle } from "./types.js";

/** `typ` header of an offline policy bundle. */
export const DEVICE_BUNDLE_TYP = "device-policy+jwt";
export const DEFAULT_BUNDLE_TTL_SECONDS = 3600;
/** Hard cap on bundle lifetime: a stolen or stale bundle is bounded to one day. */
export const MAX_BUNDLE_TTL_SECONDS = 86_400;
const SKEW_SECONDS = 30;

type BundleSigning = NonNullable<DeviceConfig["bundleSigning"]>;

function publicOf(jwk: JWK, kid: string, alg: string): JWK {
	const pub: JWK = { kty: jwk.kty, kid, alg, use: "sig" };
	if (jwk.crv !== undefined) pub.crv = jwk.crv;
	if (jwk.x !== undefined) pub.x = jwk.x;
	if (jwk.y !== undefined) pub.y = jwk.y;
	return pub;
}

/** Public verification keys for bundles, current first. Serve at `GET /device/jwks`. */
export function deviceBundleJwks(signing: BundleSigning | undefined): { keys: JWK[] } {
	if (!signing) return { keys: [] };
	const keys = [publicOf(signing.privateKey, signing.kid, signing.alg)];
	for (const prev of signing.previous ?? []) {
		if (prev.kid !== signing.kid) keys.push(publicOf(prev.publicKey, prev.kid, signing.alg));
	}
	return { keys };
}

export function clampBundleTtl(
	requested: number | undefined,
	configured: number | undefined,
): number {
	const ttl = requested ?? configured ?? DEFAULT_BUNDLE_TTL_SECONDS;
	if (!Number.isFinite(ttl) || ttl < 60) return 60;
	return Math.min(Math.floor(ttl), MAX_BUNDLE_TTL_SECONDS);
}

export interface SignBundleInput {
	signing: BundleSigning;
	issuer: string;
	deviceId: string;
	ownerId: string;
	groups: string[];
	permissions: Permission[];
	ttlSeconds: number;
	nowMs?: number;
}

/** Sign an offline policy bundle (compact JWS). */
export async function signDeviceBundle(input: SignBundleInput): Promise<IssuedDeviceBundle> {
	const nowMs = input.nowMs ?? Date.now();
	const iat = Math.floor(nowMs / 1000);
	const claims: DeviceBundleClaims = {
		iss: input.issuer,
		sub: input.deviceId,
		aud: input.deviceId,
		iat,
		nbf: iat,
		exp: iat + input.ttlSeconds,
		jti: generateId(),
		seq: nowMs,
		owner: input.ownerId,
		groups: input.groups,
		perms: input.permissions.map(stripRelation),
	};
	const key = await importJWK(input.signing.privateKey, input.signing.alg);
	const token = await new SignJWT({ ...claims })
		.setProtectedHeader({ alg: input.signing.alg, typ: DEVICE_BUNDLE_TYP, kid: input.signing.kid })
		.sign(key);
	return { token, claims };
}

/** ReBAC relations need the server graph, so a bundle never carries a permission that depends on one. */
function stripRelation(p: Permission): Permission {
	const out: Permission = { resource: p.resource, actions: [...p.actions] };
	if (p.constraints) out.constraints = p.constraints;
	return out;
}

export interface VerifyBundleOptions {
	/** Public keys: a JWKS object (from `GET /device/jwks`) or a jose key resolver. */
	keys: { keys: JWK[] } | JWTVerifyGetKey;
	deviceId: string;
	issuer?: string;
	/** Highest `seq` this device accepted before. A lower one is a rollback and is refused. */
	lastSeq?: number;
	now?: Date;
}

export type VerifyBundleResult =
	| { ok: true; claims: DeviceBundleClaims }
	| { ok: false; reason: "invalid" | "wrong_device" | "rollback"; message: string };

/**
 * Device side check of a bundle: signature, typ, iss, sub and aud equal the device id, nbf and exp with 30 s skew, seq not lower than the last accepted. Runs anywhere jose runs (gateways, Workers, Node).
 */
export async function verifyDeviceBundle(
	token: string,
	options: VerifyBundleOptions,
): Promise<VerifyBundleResult> {
	const getKey =
		typeof options.keys === "function" ? options.keys : createLocalJWKSet(options.keys);
	let payload: Record<string, unknown>;
	try {
		const verified = await jwtVerify(token, getKey, {
			typ: DEVICE_BUNDLE_TYP,
			algorithms: ["ES256", "EdDSA"],
			issuer: options.issuer ?? "theauth",
			clockTolerance: SKEW_SECONDS,
			currentDate: options.now,
		});
		payload = verified.payload as Record<string, unknown>;
	} catch {
		return {
			ok: false,
			reason: "invalid",
			message: "Bundle signature, issuer or lifetime is invalid",
		};
	}
	if (payload.sub !== options.deviceId || payload.aud !== options.deviceId) {
		return { ok: false, reason: "wrong_device", message: "Bundle was issued for another device" };
	}
	if (typeof payload.seq !== "number" || !Array.isArray(payload.perms)) {
		return { ok: false, reason: "invalid", message: "Bundle is missing seq or perms" };
	}
	if (options.lastSeq !== undefined && payload.seq < options.lastSeq) {
		return { ok: false, reason: "rollback", message: "Bundle is older than the last one accepted" };
	}
	return { ok: true, claims: payload as unknown as DeviceBundleClaims };
}

export interface BundleDecisionInput {
	action: string;
	resource: string;
	arguments?: Record<string, unknown>;
	ip?: string;
	/** Calls this device made to the resource in the last hour, counted locally. Required when the permission has `maxCallsPerHour`. */
	callsInLastHour?: number;
	now?: Date;
}

export interface BundleDecision {
	allowed: boolean;
	code: DecisionCode;
	reason?: string;
}

/**
 * Decide offline from a verified bundle. Same matcher and constraint walk as the server, with two fail closed rules: `requireApproval` always denies (no human is reachable offline) and `maxCallsPerHour` denies when the caller has no local count.
 */
export function evaluateDeviceBundle(
	claims: DeviceBundleClaims,
	input: BundleDecisionInput,
): BundleDecision {
	const now = input.now ?? new Date();
	if (now.getTime() / 1000 > claims.exp + SKEW_SECONDS) {
		return { allowed: false, code: DECISION_CODES.DEVICE_EXPIRED, reason: "Bundle has expired" };
	}
	const match = findMatchingPermission(claims.perms, input.action, input.resource);
	if (!match) {
		return {
			allowed: false,
			code: DECISION_CODES.NO_PERMISSION,
			reason: `Bundle grants no "${input.action}" on "${input.resource}"`,
		};
	}
	const constraints = match.permission.constraints;
	if (!constraints) return { allowed: true, code: DECISION_CODES.ALLOWED };
	if (constraints.requireApproval) {
		return {
			allowed: false,
			code: DECISION_CODES.APPROVAL_REQUIRED,
			reason: "Approval needs the server; denied offline",
		};
	}
	if (constraints.maxCallsPerHour != null && input.callsInLastHour === undefined) {
		return {
			allowed: false,
			code: DECISION_CODES.RATE_LIMITED,
			reason: "Rate limited permission needs a local call count offline",
		};
	}
	const inspection = inspectConstraints(
		{ subjectId: claims.sub, resource: input.resource, arguments: input.arguments, ip: input.ip },
		constraints,
		{ now, rateUsage: input.callsInLastHour },
	);
	if (!inspection.allowed) {
		return {
			allowed: false,
			code: inspection.code ?? DECISION_CODES.NO_PERMISSION,
			reason: inspection.reason,
		};
	}
	return { allowed: true, code: DECISION_CODES.ALLOWED };
}
