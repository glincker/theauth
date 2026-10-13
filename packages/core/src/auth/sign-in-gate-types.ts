/** Public types for the central sign-in gate. See `sign-in-gate.ts`. */

import type { TrustedDevice } from "./trusted-device.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type SignInMethod = "password" | "social" | "magic_link" | "passkey";

/** A second factor the gate can require and verify. */
export interface TwoFactorFactor {
	id: string;
	/** True when the user has enrolled and enabled this factor. */
	isEnabled(userId: string): Promise<boolean>;
	/** Verify a user-supplied code. Factors without `verify` are never offered. */
	verify(userId: string, code: string): Promise<boolean>;
}

export interface SignInGateTrustedDeviceConfig {
	/** Issue trusted-device records after a successful 2FA (default: false). */
	enabled?: boolean;
	/** Trust window in seconds (default: 30 days). */
	trustDurationSeconds?: number;
	/** Maximum trusted devices per user (default: 10). */
	maxDevices?: number;
	/** Cookie name carrying the device secret (default: `theauth_trusted_device`). */
	cookieName?: string;
}

export interface SignInGateConfig {
	/**
	 * Sign-in methods that must pass a second factor when the user has one
	 * enabled. Default when the gate is configured: password, social, magic_link.
	 * Without any gate configuration the default is none (existing behaviour).
	 */
	require2faFor?: SignInMethod[];
	/** HMAC secret for challenges and device cookies. Falls back to the session secret. */
	secret?: string;
	/** Challenge lifetime in seconds (default: 300). */
	challengeTtlSeconds?: number;
	/** Wrong-code attempts allowed per challenge (default: 5). */
	maxChallengeAttempts?: number;
	trustedDevice?: SignInGateTrustedDeviceConfig;
	/** Extra second factors besides TOTP. */
	factors?: TwoFactorFactor[];
}

export interface SignInGateUser {
	id: string;
	/** Admin-forced password change pending. */
	mustChangePassword: boolean;
}

export interface SignInGateContext {
	/** Incoming request, used to read the trusted-device cookie. */
	request?: Request;
}

export type SignInGateDecision =
	| { action: "allow" }
	| { action: "password_change_required"; challenge: string; expiresAt: Date }
	| {
			action: "two_factor_required";
			challenge: string;
			methods: string[];
			expiresAt: Date;
	  };

export type PasswordChangeOutcome = "changed" | "no_account" | { error: string };

export type PasswordChanger = (
	userId: string,
	newPassword: string,
) => Promise<PasswordChangeOutcome>;

export interface TrustedDeviceCookie {
	name: string;
	value: string;
	maxAge: number;
}

export type TwoFactorCompletion =
	| {
			ok: true;
			userId: string;
			method: SignInMethod;
			trustedDeviceCookie?: TrustedDeviceCookie;
	  }
	| { ok: false; reason: "invalid_challenge" | "invalid_code" | "too_many_attempts" };

export type PasswordChangeCompletion =
	| { ok: true; userId: string; method: SignInMethod; next: SignInGateDecision }
	| {
			ok: false;
			reason: "invalid_challenge" | "no_password_account" | "rejected";
			message?: string;
	  };

export interface SignInGate {
	/** Evaluate the gate for a user whose primary credential was just verified. */
	evaluate(
		input: { userId: string; method: SignInMethod } & SignInGateContext,
	): Promise<SignInGateDecision>;
	/** Exchange a two-factor challenge plus code for permission to issue a session. */
	completeTwoFactor(input: {
		challenge: string;
		code: string;
		factor?: string;
		trustDevice?: boolean;
		request?: Request;
	}): Promise<TwoFactorCompletion>;
	/** Complete a forced password change with a `password_change_required` challenge. */
	completePasswordChange(input: {
		challenge: string;
		newPassword: string;
		request?: Request;
	}): Promise<PasswordChangeCompletion>;
	/** Register a function able to set a new password for a credential store. */
	registerPasswordChanger(changer: PasswordChanger): void;
	/** Declare that a credential store holds passwords for some users. */
	registerPasswordCredentialCheck(check: (userId: string) => Promise<boolean>): void;
	/** Call after any password change or reset: revokes trusted devices. */
	onPasswordChanged(userId: string): Promise<void>;
	/** Clear the forced password change flag. */
	clearMustChangePassword(userId: string): Promise<void>;
	/** List active trusted devices. */
	listTrustedDevices(userId: string): Promise<TrustedDevice[]>;
	/** Revoke a trusted device by record id. Returns false when not found. */
	revokeTrustedDevice(userId: string, deviceId: string): Promise<boolean>;
	/** Revoke every trusted device of a user. */
	revokeAllTrustedDevices(userId: string): Promise<void>;
	/** Resolved configuration, for plugins and docs. */
	readonly options: {
		require2faFor: SignInMethod[];
		trustedDeviceEnabled: boolean;
		trustedDeviceCookieName: string;
		challengeTtlSeconds: number;
	};
}
