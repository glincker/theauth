/**
 * Passkey as a second factor for the central sign-in gate.
 *
 * The gate hands a `code` string to every enabled factor. For this factor the
 * code is a WebAuthn assertion (the `PublicKeyCredential` JSON the browser
 * produced), sent as a JSON string or as base64url encoded JSON. The assertion
 * is verified by the passkey module, which also consumes the one-time
 * WebAuthn challenge, and must come from a credential owned by the user the
 * gate challenge was issued for.
 *
 * Flow:
 *   1. A primary sign-in answers `twoFactorRequired` with `methods: ["passkey"]`.
 *   2. The client asks for WebAuthn options for that user:
 *      `factor.getOptions(userId)` (or the passkey module's
 *      `getAuthenticationOptions(userId)`), signs the challenge with the
 *      authenticator, and
 *   3. posts `{ challenge, factor: "passkey", code: JSON.stringify(assertion) }`
 *      to `/auth/sign-in/two-factor`.
 *
 * @example
 * ```typescript
 * const passkey = createPasskeyModule({ rpName: "App", rpId: "example.com", origin }, db);
 * const theauth = await createTheAuth({
 *   database: { provider: "sqlite", url: "theauth.db" },
 *   auth: { session: { secret: process.env.SESSION_SECRET } },
 *   signInGate: {
 *     require2faFor: ["password", "social", "magic_link", "phone"],
 *     factors: [createPasskeyTwoFactorFactor(passkey)],
 *   },
 * });
 * ```
 */

import { fromBase64Url } from "../crypto/web-crypto.js";
import type { PasskeyModule } from "./passkey.js";
import type { TwoFactorFactor } from "./sign-in-gate-types.js";

type Assertion = Parameters<PasskeyModule["verifyAuthentication"]>[0];

export interface PasskeyTwoFactorFactor extends TwoFactorFactor {
	/**
	 * WebAuthn request options (challenge, allowCredentials) for the user the
	 * gate challenge belongs to. Call this before the browser prompt.
	 */
	getOptions(userId: string): ReturnType<PasskeyModule["getAuthenticationOptions"]>;
}

export interface PasskeyTwoFactorOptions {
	/** Factor id reported in `methods` and matched by `factor` (default: `passkey`). */
	id?: string;
}

function isObject(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null;
}

/** Decode a JSON or base64url JSON assertion. Null when the shape is wrong. */
function parseAssertion(code: string): Assertion | null {
	let raw: unknown;
	try {
		const trimmed = code.trim();
		raw = trimmed.startsWith("{")
			? JSON.parse(trimmed)
			: JSON.parse(new TextDecoder().decode(fromBase64Url(trimmed)));
	} catch {
		return null;
	}
	if (!isObject(raw) || !isObject(raw.response)) return null;
	const r = raw.response;
	if (
		typeof raw.id !== "string" ||
		raw.type !== "public-key" ||
		typeof r.clientDataJSON !== "string" ||
		typeof r.authenticatorData !== "string" ||
		typeof r.signature !== "string"
	) {
		return null;
	}
	return {
		id: raw.id,
		rawId: typeof raw.rawId === "string" ? raw.rawId : raw.id,
		type: "public-key",
		response: {
			clientDataJSON: r.clientDataJSON,
			authenticatorData: r.authenticatorData,
			signature: r.signature,
		},
	};
}

/**
 * Build a `TwoFactorFactor` backed by a passkey module. Enabled for users who
 * have at least one registered passkey. Verification fails closed: any parse
 * or WebAuthn error, or an assertion from another user's credential, is a
 * wrong code.
 */
export function createPasskeyTwoFactorFactor(
	passkey: PasskeyModule,
	options: PasskeyTwoFactorOptions = {},
): PasskeyTwoFactorFactor {
	return {
		id: options.id ?? "passkey",
		async isEnabled(userId) {
			const credentials = await passkey.listCredentials(userId);
			return credentials.length > 0;
		},
		async verify(userId, code) {
			const assertion = parseAssertion(code);
			if (!assertion) return false;
			try {
				const result = await passkey.verifyAuthentication(assertion);
				return result.userId === userId;
			} catch {
				return false;
			}
		},
		getOptions: (userId) => passkey.getAuthenticationOptions(userId),
	};
}
