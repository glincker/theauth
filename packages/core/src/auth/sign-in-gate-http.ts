/** HTTP helpers and the error type for the central sign-in gate. */

import type { SignInGateDecision } from "./sign-in-gate-types.js";

/**
 * Thrown by session-issuing modules when the gate does not allow a session.
 * Carries the decision so HTTP layers can answer with the challenge.
 */
export class SignInGateError extends Error {
	readonly code: "PASSWORD_RESET_REQUIRED" | "TWO_FACTOR_REQUIRED";
	readonly decision: Exclude<SignInGateDecision, { action: "allow" }>;

	constructor(decision: Exclude<SignInGateDecision, { action: "allow" }>) {
		super(
			decision.action === "password_change_required"
				? "Password reset required"
				: "Two-factor authentication required",
		);
		this.name = "SignInGateError";
		this.decision = decision;
		this.code =
			decision.action === "password_change_required"
				? "PASSWORD_RESET_REQUIRED"
				: "TWO_FACTOR_REQUIRED";
	}
}

/**
 * Standard HTTP answer for a gate error: 403 `PASSWORD_RESET_REQUIRED` with a
 * password-change challenge, or 200 `{ twoFactorRequired: true, ... }` with a
 * two-factor challenge. No session is ever included.
 */
export function signInGateResponse(err: SignInGateError): Response {
	const decision = err.decision;
	if (decision.action === "password_change_required") {
		return new Response(
			JSON.stringify({
				error: {
					code: "PASSWORD_RESET_REQUIRED",
					message: "You must change your password before signing in",
				},
				passwordChangeRequired: true,
				challenge: decision.challenge,
				expiresAt: decision.expiresAt,
			}),
			{ status: 403, headers: { "Content-Type": "application/json" } },
		);
	}
	return new Response(
		JSON.stringify({
			twoFactorRequired: true,
			challenge: decision.challenge,
			methods: decision.methods,
			expiresAt: decision.expiresAt,
		}),
		{ status: 200, headers: { "Content-Type": "application/json" } },
	);
}

/**
 * Redirect variant for browser flows (OAuth callback). The challenge travels
 * in the URL fragment so it is not sent to servers or logged in referrers:
 * `<location>#gate=two_factor_required&challenge=...&methods=totp`.
 */
export function signInGateRedirect(
	location: string,
	decision: Exclude<SignInGateDecision, { action: "allow" }>,
	setCookies: string[] = [],
): Response {
	const params = new URLSearchParams({
		gate: decision.action,
		challenge: decision.challenge,
	});
	if (decision.action === "two_factor_required") {
		params.set("methods", decision.methods.join(","));
	}
	const headers = new Headers({ Location: `${location}#${params.toString()}` });
	for (const cookie of setCookies) headers.append("Set-Cookie", cookie);
	return new Response(null, { status: 302, headers });
}
