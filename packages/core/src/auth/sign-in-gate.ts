/**
 * Central sign-in gate.
 *
 * Every path that issues a session (username, email/password, magic link,
 * OAuth callback, passkey, phone, email OTP, one tap, device) calls the gate once the primary credential has been
 * verified. The gate answers one question: may a session be issued now?
 *
 * Outcomes:
 *   - `allow`: issue the session.
 *   - `password_change_required`: the account is flagged for a forced password
 *     change. A signed challenge is returned so the user can complete the
 *     change flow without a session.
 *   - `two_factor_required`: the account has a second factor enabled, the
 *     sign-in method is listed in `require2faFor`, and no valid trusted device
 *     cookie was presented. A signed challenge is returned; exchange it with a
 *     code through `completeTwoFactor`.
 *
 * Challenges are stateless HMAC-signed tokens (default TTL 5 minutes). Attempt
 * counting and single-use tracking are per process (in memory).
 *
 * Trusted devices are bound to a random cookie secret issued after a
 * successful second factor, never to request headers alone, so a spoofed
 * user-agent cannot skip 2FA.
 */

import { eq } from "drizzle-orm";
import {
	constantTimeEqual,
	fromBase64Url,
	fromHex,
	hmacSha256,
	randomBytesHex,
	toBase64Url,
} from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { usernameAccounts, users } from "../db/schema.js";
import type {
	PasswordChangeCompletion,
	PasswordChangeOutcome,
	PasswordChanger,
	SignInGate,
	SignInGateConfig,
	SignInGateContext,
	SignInGateDecision,
	SignInGateUser,
	SignInMethod,
	TwoFactorCompletion,
	TwoFactorFactor,
} from "./sign-in-gate-types.js";
import { SIGN_IN_METHODS } from "./sign-in-gate-types.js";
import type { TotpModule } from "./totp.js";
import { createTotpModule } from "./totp.js";
import { createTrustedDeviceModule } from "./trusted-device.js";

export { SignInGateError, signInGateRedirect, signInGateResponse } from "./sign-in-gate-http.js";
export type {
	PasswordChangeCompletion,
	PasswordChangeOutcome,
	PasswordChanger,
	SignInGate,
	SignInGateConfig,
	SignInGateContext,
	SignInGateDecision,
	SignInGateTrustedDeviceConfig,
	SignInGateUser,
	SignInMethod,
	TrustedDeviceCookie,
	TwoFactorCompletion,
	TwoFactorFactor,
} from "./sign-in-gate-types.js";
export { SIGN_IN_METHODS } from "./sign-in-gate-types.js";

// ---------------------------------------------------------------------------
// Pure evaluation
// ---------------------------------------------------------------------------

export interface EvaluateSignInGateInput {
	user: SignInGateUser;
	method: SignInMethod;
	policy: { require2faFor: readonly SignInMethod[] };
	/** The user can sign in with a password, so a forced change is completable. */
	hasPasswordCredential: boolean;
	/** Enabled factor ids that can be verified with a code. */
	enabledFactors: readonly string[];
	/** A valid trusted-device record was presented. */
	deviceTrusted: boolean;
}

export type RawGateOutcome = "allow" | "password_change_required" | "two_factor_required";

/**
 * Decide the outcome from already-resolved facts. Forced password change wins
 * over 2FA (the change flow re-evaluates the gate afterwards). A forced change
 * only blocks methods other than `password` when the user actually has a
 * password credential, so social-only accounts cannot be locked out.
 */
export function evaluateSignInGate(input: EvaluateSignInGateInput): RawGateOutcome {
	if (input.user.mustChangePassword && input.hasPasswordCredential) {
		return "password_change_required";
	}
	if (
		input.policy.require2faFor.includes(input.method) &&
		input.enabledFactors.length > 0 &&
		!input.deviceTrusted
	) {
		return "two_factor_required";
	}
	return "allow";
}

// ---------------------------------------------------------------------------
// Challenge tokens
// ---------------------------------------------------------------------------

type ChallengePurpose = "password_change" | "two_factor";

interface ChallengePayload {
	p: ChallengePurpose;
	u: string;
	m: SignInMethod;
	e: number;
	j: string;
}

const CHALLENGE_PREFIX = "theauth:sign-in-gate:v1:";
const DEFAULT_CHALLENGE_TTL = 300;
const DEFAULT_MAX_ATTEMPTS = 5;
const DEFAULT_TRUST_SECONDS = 30 * 24 * 60 * 60;
const DEFAULT_COOKIE_NAME = "theauth_trusted_device";
const DEFAULT_REQUIRE_2FA: SignInMethod[] = ["password", "social", "magic_link"];
const MAX_TRACKED = 10_000;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function readCookie(request: Request | undefined, name: string): string | null {
	const header = request?.headers.get("cookie");
	if (!header) return null;
	for (const part of header.split(";")) {
		const idx = part.indexOf("=");
		if (idx === -1) continue;
		if (part.slice(0, idx).trim() === name) {
			try {
				return decodeURIComponent(part.slice(idx + 1).trim());
			} catch {
				return null;
			}
		}
	}
	return null;
}

function isMethod(value: unknown): value is SignInMethod {
	return typeof value === "string" && (SIGN_IN_METHODS as readonly string[]).includes(value);
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export interface CreateSignInGateOptions {
	db: Database;
	config?: SignInGateConfig;
	/** Fallback signing secret (the session secret). */
	sessionSecret?: string;
	/** TOTP module to read enrollment from. Defaults to a module over `db`. */
	totp?: TotpModule;
	/**
	 * Whether the TOTP tables exist. The built-in TOTP factor is only
	 * registered when true, so the gate never queries a missing table.
	 * Defaults to true for callers that create every table.
	 */
	totpAvailable?: boolean;
	/**
	 * Whether the username account table exists. The built-in password
	 * credential check is skipped when false. Defaults to true.
	 */
	usernameAccountsAvailable?: boolean;
}

export function createSignInGate(options: CreateSignInGateOptions): SignInGate {
	const { db } = options;
	const config = options.config;
	const require2faFor = config?.require2faFor ?? (config ? DEFAULT_REQUIRE_2FA : []);
	const ttl = config?.challengeTtlSeconds ?? DEFAULT_CHALLENGE_TTL;
	const maxAttempts = config?.maxChallengeAttempts ?? DEFAULT_MAX_ATTEMPTS;
	const secret = config?.secret ?? options.sessionSecret ?? randomBytesHex(32);
	const td = config?.trustedDevice;
	const trustedEnabled = td?.enabled === true;
	const trustSeconds = td?.trustDurationSeconds ?? DEFAULT_TRUST_SECONDS;
	const cookieName = td?.cookieName ?? DEFAULT_COOKIE_NAME;

	const totp = options.totp ?? createTotpModule({}, db);
	const trusted = createTrustedDeviceModule(
		{
			trustDurationSeconds: trustSeconds,
			...(td?.maxDevices !== undefined && { maxDevices: td.maxDevices }),
			secret,
		},
		db,
	);

	const totpAvailable = options.totpAvailable ?? true;
	const usernameAccountsAvailable = options.usernameAccountsAvailable ?? true;

	const factors: TwoFactorFactor[] = [
		...(totpAvailable
			? [
					{
						id: "totp",
						isEnabled: (userId: string) => totp.isEnabled(userId),
						async verify(userId: string, code: string) {
							const result = await totp.verify(userId, code);
							return result.valid;
						},
					},
				]
			: []),
		...(config?.factors ?? []),
	];

	const passwordChangers: PasswordChanger[] = [];
	const credentialChecks: Array<(userId: string) => Promise<boolean>> = usernameAccountsAvailable
		? [
				async (userId) => {
					const rows = await db
						.select({ id: usernameAccounts.id })
						.from(usernameAccounts)
						.where(eq(usernameAccounts.userId, userId));
					return rows.length > 0;
				},
			]
		: [];

	const attempts = new Map<string, number>();
	const consumed = new Map<string, number>();

	function prune(): void {
		const nowSec = Math.floor(Date.now() / 1000);
		for (const [jti, exp] of consumed) if (exp < nowSec) consumed.delete(jti);
		if (attempts.size > MAX_TRACKED) attempts.clear();
		if (consumed.size > MAX_TRACKED) consumed.clear();
	}

	async function sign(payload: ChallengePayload): Promise<string> {
		const body = toBase64Url(encoder.encode(JSON.stringify(payload)));
		const mac = await hmacSha256(secret, CHALLENGE_PREFIX + body);
		return `${body}.${mac}`;
	}

	async function verifyChallenge(
		token: string,
		purpose: ChallengePurpose,
	): Promise<ChallengePayload | null> {
		const dot = token.indexOf(".");
		if (dot <= 0) return null;
		const body = token.slice(0, dot);
		const mac = token.slice(dot + 1);
		const expected = await hmacSha256(secret, CHALLENGE_PREFIX + body);
		if (!/^[0-9a-f]+$/.test(mac) || mac.length !== expected.length) return null;
		if (!constantTimeEqual(fromHex(mac), fromHex(expected))) return null;
		let parsed: unknown;
		try {
			parsed = JSON.parse(decoder.decode(fromBase64Url(body)));
		} catch {
			return null;
		}
		if (typeof parsed !== "object" || parsed === null) return null;
		const p = parsed as Record<string, unknown>;
		if (
			p.p !== purpose ||
			typeof p.u !== "string" ||
			!isMethod(p.m) ||
			typeof p.e !== "number" ||
			typeof p.j !== "string"
		) {
			return null;
		}
		if (p.e < Math.floor(Date.now() / 1000)) return null;
		if (consumed.has(p.j)) return null;
		return { p: purpose, u: p.u, m: p.m, e: p.e, j: p.j };
	}

	async function issueChallenge(
		purpose: ChallengePurpose,
		userId: string,
		method: SignInMethod,
	): Promise<{ token: string; expiresAt: Date }> {
		const exp = Math.floor(Date.now() / 1000) + ttl;
		const token = await sign({ p: purpose, u: userId, m: method, e: exp, j: randomBytesHex(16) });
		return { token, expiresAt: new Date(exp * 1000) };
	}

	async function loadUser(userId: string): Promise<SignInGateUser> {
		const rows = await db
			.select({ id: users.id, forcePasswordReset: users.forcePasswordReset })
			.from(users)
			.where(eq(users.id, userId));
		const row = rows[0];
		return { id: userId, mustChangePassword: row?.forcePasswordReset === 1 };
	}

	async function hasPasswordCredential(userId: string, method: SignInMethod): Promise<boolean> {
		// The user just proved a password: a forced change is always completable.
		if (method === "password") return true;
		for (const check of credentialChecks) {
			if (await check(userId)) return true;
		}
		return false;
	}

	async function deviceFingerprint(userId: string, deviceSecret: string): Promise<string> {
		return hmacSha256(secret, `trusted-device:${userId}:${deviceSecret}`);
	}

	async function isDeviceTrusted(userId: string, request?: Request): Promise<boolean> {
		if (!trustedEnabled) return false;
		const deviceSecret = readCookie(request, cookieName);
		if (!deviceSecret) return false;
		return trusted.isTrusted(userId, await deviceFingerprint(userId, deviceSecret));
	}

	async function enabledFactorIds(userId: string): Promise<string[]> {
		const ids: string[] = [];
		for (const factor of factors) {
			if (await factor.isEnabled(userId)) ids.push(factor.id);
		}
		return ids;
	}

	async function evaluate(
		input: { userId: string; method: SignInMethod } & SignInGateContext,
	): Promise<SignInGateDecision> {
		const user = await loadUser(input.userId);
		const needsPwCheck = user.mustChangePassword;
		const needs2fa = require2faFor.includes(input.method);
		const hasPassword = needsPwCheck ? await hasPasswordCredential(user.id, input.method) : false;
		const enabled =
			needs2fa && !(needsPwCheck && hasPassword) ? await enabledFactorIds(user.id) : [];
		const verifiable = enabled.filter((id) => factors.some((f) => f.id === id));
		const deviceTrusted =
			verifiable.length > 0 && !(needsPwCheck && hasPassword)
				? await isDeviceTrusted(user.id, input.request)
				: false;

		const outcome = evaluateSignInGate({
			user,
			method: input.method,
			policy: { require2faFor },
			hasPasswordCredential: hasPassword,
			enabledFactors: verifiable,
			deviceTrusted,
		});

		if (outcome === "allow") return { action: "allow" };
		if (outcome === "password_change_required") {
			const { token, expiresAt } = await issueChallenge("password_change", user.id, input.method);
			return { action: "password_change_required", challenge: token, expiresAt };
		}
		const { token, expiresAt } = await issueChallenge("two_factor", user.id, input.method);
		return { action: "two_factor_required", challenge: token, methods: verifiable, expiresAt };
	}

	async function completeTwoFactor(input: {
		challenge: string;
		code: string;
		factor?: string;
		trustDevice?: boolean;
		request?: Request;
	}): Promise<TwoFactorCompletion> {
		prune();
		const payload = await verifyChallenge(input.challenge, "two_factor");
		if (!payload) return { ok: false, reason: "invalid_challenge" };

		const used = attempts.get(payload.j) ?? 0;
		if (used >= maxAttempts) return { ok: false, reason: "too_many_attempts" };
		attempts.set(payload.j, used + 1);

		const enabled = await enabledFactorIds(payload.u);
		const candidates = factors.filter(
			(f) => enabled.includes(f.id) && (input.factor === undefined || f.id === input.factor),
		);
		let valid = false;
		for (const factor of candidates) {
			if (await factor.verify(payload.u, input.code)) {
				valid = true;
				break;
			}
		}
		if (!valid) return { ok: false, reason: "invalid_code" };

		consumed.set(payload.j, payload.e);
		attempts.delete(payload.j);

		const completion: TwoFactorCompletion = { ok: true, userId: payload.u, method: payload.m };
		if (trustedEnabled && input.trustDevice === true) {
			const deviceSecret = randomBytesHex(32);
			await trusted.trustDevice(payload.u, await deviceFingerprint(payload.u, deviceSecret));
			completion.trustedDeviceCookie = {
				name: cookieName,
				value: deviceSecret,
				maxAge: trustSeconds,
			};
		}
		return completion;
	}

	async function clearMustChangePassword(userId: string): Promise<void> {
		await db
			.update(users)
			.set({ forcePasswordReset: 0, updatedAt: new Date() })
			.where(eq(users.id, userId));
	}

	async function onPasswordChanged(userId: string): Promise<void> {
		await trusted.revokeAllDevices(userId);
	}

	async function completePasswordChange(input: {
		challenge: string;
		newPassword: string;
		request?: Request;
	}): Promise<PasswordChangeCompletion> {
		prune();
		const payload = await verifyChallenge(input.challenge, "password_change");
		if (!payload) return { ok: false, reason: "invalid_challenge" };

		let outcome: PasswordChangeOutcome = "no_account";
		for (const changer of passwordChangers) {
			outcome = await changer(payload.u, input.newPassword);
			if (outcome !== "no_account") break;
		}
		if (outcome === "no_account") return { ok: false, reason: "no_password_account" };
		if (outcome !== "changed") {
			return { ok: false, reason: "rejected", message: outcome.error };
		}

		consumed.set(payload.j, payload.e);
		await clearMustChangePassword(payload.u);
		await onPasswordChanged(payload.u);

		const next = await evaluate({
			userId: payload.u,
			method: payload.m,
			...(input.request && { request: input.request }),
		});
		return { ok: true, userId: payload.u, method: payload.m, next };
	}

	async function revokeTrustedDevice(userId: string, deviceId: string): Promise<boolean> {
		const devices = await trusted.listDevices(userId);
		const match = devices.find((d) => d.id === deviceId);
		if (!match) return false;
		await trusted.revokeDevice(userId, match.fingerprint);
		return true;
	}

	return {
		evaluate,
		completeTwoFactor,
		completePasswordChange,
		registerPasswordChanger(changer) {
			passwordChangers.push(changer);
		},
		registerPasswordCredentialCheck(check) {
			credentialChecks.push(check);
		},
		onPasswordChanged,
		clearMustChangePassword,
		listTrustedDevices: (userId) => trusted.listDevices(userId),
		revokeTrustedDevice,
		revokeAllTrustedDevices: (userId) => trusted.revokeAllDevices(userId),
		options: {
			require2faFor,
			trustedDeviceEnabled: trustedEnabled,
			trustedDeviceCookieName: cookieName,
			challengeTtlSeconds: ttl,
		},
	};
}
