/**
 * Browser passkey client for the TypeScript server's passkey plugin.
 *
 * `signIn({ conditional: true })` starts a conditional (autofill) request: the
 * browser offers saved passkeys in the username field's suggestions, and the
 * promise resolves only if the user picks one. Pair it with an input that has
 * `autocomplete="username webauthn"`.
 */

import {
	assertionToJSON,
	attestationToJSON,
	creationOptionsFromJSON,
	requestOptionsFromJSON,
} from "./webauthn.js";

export interface PasskeyClientOptions {
	/** Where the auth routes are mounted, e.g. `/api/theauth`. */
	baseUrl: string;
	fetch?: typeof fetch;
	/** Send cookies. Default `"include"`. */
	credentials?: RequestCredentials;
	/** Extra headers on every call. */
	headers?: HeadersInit;
}

export interface PasskeySignInOptions {
	/** Limit to one user's credentials. Not needed for discoverable passkeys. */
	userId?: string;
	/** Use conditional UI (autofill) instead of a modal prompt. */
	conditional?: boolean;
	/** Abort a pending prompt, e.g. when the form unmounts. */
	signal?: AbortSignal;
}

export type PasskeyResult<T> =
	| { ok: true; data: T }
	| {
			ok: false;
			/** `cancelled` for a dismissed or aborted prompt, `unsupported`, or `failed`. */
			reason: "cancelled" | "unsupported" | "failed";
			message: string;
			status?: number;
	  };

export interface PasskeySession {
	user: { id: string };
	session?: { token: string; expiresAt?: string };
}

export interface PasskeyClient {
	/** WebAuthn is available in this browser. */
	isSupported(): boolean;
	/** The browser can show passkeys in an autofill dropdown. */
	isConditionalAvailable(): Promise<boolean>;
	signIn(options?: PasskeySignInOptions): Promise<PasskeyResult<PasskeySession>>;
	/** Add a passkey to the signed-in user. */
	register(deviceName?: string): Promise<PasskeyResult<{ credentialId: string }>>;
}

function trimSlashes(value: string): string {
	let end = value.length;
	while (end > 0 && value.charCodeAt(end - 1) === 47) end--;
	return value.slice(0, end);
}

function isCancel(err: unknown): boolean {
	return (
		err instanceof DOMException && (err.name === "NotAllowedError" || err.name === "AbortError")
	);
}

export function createPasskeyClient(options: PasskeyClientOptions): PasskeyClient {
	const base = trimSlashes(options.baseUrl);
	const doFetch = options.fetch ?? ((...a: Parameters<typeof fetch>) => fetch(...a));
	const credentials = options.credentials ?? "include";

	const supported = (): boolean =>
		typeof globalThis.PublicKeyCredential !== "undefined" &&
		typeof navigator !== "undefined" &&
		typeof navigator.credentials !== "undefined";

	async function post(path: string, body: unknown): Promise<Response> {
		const headers = new Headers(options.headers);
		headers.set("Content-Type", "application/json");
		return doFetch(`${base}${path}`, {
			method: "POST",
			headers,
			body: JSON.stringify(body),
			credentials,
		});
	}

	async function errorOf(res: Response, fallback: string): Promise<string> {
		try {
			const json = (await res.json()) as { error?: string | { message?: string } };
			if (typeof json.error === "string") return json.error;
			return json.error?.message ?? fallback;
		} catch {
			return fallback;
		}
	}

	const unsupported = {
		ok: false,
		reason: "unsupported",
		message: "Passkeys are not supported",
	} as const;

	return {
		isSupported: supported,

		async isConditionalAvailable() {
			if (!supported()) return false;
			const pkc = globalThis.PublicKeyCredential as unknown as {
				isConditionalMediationAvailable?: () => Promise<boolean>;
			};
			return (await pkc.isConditionalMediationAvailable?.()) === true;
		},

		async signIn(opts = {}) {
			if (!supported()) return unsupported;
			const optionsRes = await post("/auth/passkey/authenticate/options", {
				...(opts.userId ? { userId: opts.userId } : {}),
			});
			if (!optionsRes.ok) {
				return {
					ok: false,
					reason: "failed",
					status: optionsRes.status,
					message: await errorOf(optionsRes, "Could not start passkey sign-in"),
				};
			}
			const serverOptions = (await optionsRes.json()) as Parameters<
				typeof requestOptionsFromJSON
			>[0]["publicKey"];

			let credential: Credential | null;
			try {
				credential = await navigator.credentials.get({
					publicKey: requestOptionsFromJSON({ publicKey: serverOptions }),
					...(opts.conditional
						? { mediation: "conditional" as CredentialMediationRequirement }
						: {}),
					signal: opts.signal,
				});
			} catch (err) {
				if (isCancel(err))
					return { ok: false, reason: "cancelled", message: "Passkey prompt dismissed" };
				return {
					ok: false,
					reason: "failed",
					message: err instanceof Error ? err.message : "Passkey sign-in failed",
				};
			}
			if (!credential) return { ok: false, reason: "cancelled", message: "No passkey was chosen" };

			const verifyRes = await post("/auth/passkey/authenticate/verify", {
				response: assertionToJSON(credential as PublicKeyCredential),
			});
			if (!verifyRes.ok) {
				return {
					ok: false,
					reason: "failed",
					status: verifyRes.status,
					message: await errorOf(verifyRes, "Passkey sign-in failed"),
				};
			}
			return { ok: true, data: (await verifyRes.json()) as PasskeySession };
		},

		async register(deviceName) {
			if (!supported()) return unsupported;
			const optionsRes = await post("/auth/passkey/register/options", {});
			if (!optionsRes.ok) {
				return {
					ok: false,
					reason: "failed",
					status: optionsRes.status,
					message: await errorOf(optionsRes, "Could not start passkey setup"),
				};
			}
			const serverOptions = (await optionsRes.json()) as Parameters<
				typeof creationOptionsFromJSON
			>[0]["publicKey"];

			let credential: Credential | null;
			try {
				credential = await navigator.credentials.create({
					publicKey: creationOptionsFromJSON({ publicKey: serverOptions }),
				});
			} catch (err) {
				if (isCancel(err))
					return { ok: false, reason: "cancelled", message: "Passkey setup dismissed" };
				return {
					ok: false,
					reason: "failed",
					message: err instanceof Error ? err.message : "Passkey setup failed",
				};
			}
			if (!credential) return { ok: false, reason: "cancelled", message: "No passkey was created" };

			const attestation = attestationToJSON(credential as PublicKeyCredential) as {
				response: { transports?: string[] };
			};
			const verifyRes = await post("/auth/passkey/register/verify", {
				response: {
					...attestation,
					transports: attestation.response.transports ?? [],
					...(deviceName ? { deviceName } : {}),
				},
			});
			if (!verifyRes.ok) {
				return {
					ok: false,
					reason: "failed",
					status: verifyRes.status,
					message: await errorOf(verifyRes, "Passkey setup failed"),
				};
			}
			const body = (await verifyRes.json()) as { credential?: { id?: string } };
			return { ok: true, data: { credentialId: body.credential?.id ?? "" } };
		},
	};
}
