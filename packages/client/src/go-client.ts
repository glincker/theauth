import type {
	GoAuthError,
	GoAuthResult,
	GoUser,
	LoginResult,
	PasskeyCredential,
	TheAuthGoClient,
	TheAuthGoClientOptions,
	TotpEnrollment,
} from "./go-types.js";
import type { CreationOptionsJSON, RequestOptionsJSON } from "./webauthn.js";
import {
	assertionToJSON,
	attestationToJSON,
	creationOptionsFromJSON,
	isPasskeySupported,
	requestOptionsFromJSON,
} from "./webauthn.js";

export const GO_ERROR_NETWORK = "NETWORK_ERROR";
export const GO_ERROR_PASSKEY_UNSUPPORTED = "PASSKEY_UNSUPPORTED";
export const GO_ERROR_PASSKEY_CANCELLED = "PASSKEY_CANCELLED";
export const GO_ERROR_HTTP = "HTTP_ERROR";

interface Wire {
	status: number;
	body: unknown;
	retryAfter?: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null;
}

function toError(wire: Wire): GoAuthError {
	const { body, status, retryAfter } = wire;
	if (isRecord(body) && typeof body.code === "string") {
		return {
			code: body.code,
			message: typeof body.message === "string" ? body.message : "",
			status,
			retryAfter,
		};
	}
	return {
		code: GO_ERROR_HTTP,
		message: typeof body === "string" ? body : "",
		status,
		retryAfter,
	};
}

function fail<T>(error: GoAuthError): GoAuthResult<T> {
	return { success: false, error };
}

function ok<T>(data: T): GoAuthResult<T> {
	return { success: true, data };
}

export function createTheAuthGoClient(options: TheAuthGoClientOptions = {}): TheAuthGoClient {
	const prefix = `${(options.baseUrl ?? "").replace(/\/$/, "")}${options.basePath ?? "/auth"}`;

	async function send(path: string, method: string, body?: unknown): Promise<GoAuthResult<Wire>> {
		const doFetch = options.fetch ?? globalThis.fetch;
		let res: Response;
		try {
			res = await doFetch(`${prefix}${path}`, {
				method,
				credentials: options.credentials ?? "include",
				headers: {
					...(body === undefined ? {} : { "Content-Type": "application/json" }),
					...options.headers,
				},
				body: body === undefined ? undefined : JSON.stringify(body),
			});
		} catch (err) {
			return fail({
				code: GO_ERROR_NETWORK,
				message: err instanceof Error ? err.message : "",
				status: 0,
			});
		}
		const text = res.status === 204 ? "" : await res.text();
		let parsed: unknown = text;
		if (text) {
			try {
				parsed = JSON.parse(text);
			} catch {
				parsed = text;
			}
		} else {
			parsed = null;
		}
		const header = res.headers?.get?.("Retry-After");
		const retryAfter = header && Number.isFinite(Number(header)) ? Number(header) : undefined;
		const wire: Wire = { status: res.status, body: parsed, retryAfter };
		if (!res.ok) return fail(toError(wire));
		return ok(wire);
	}

	async function call<T>(
		path: string,
		method: string,
		body?: unknown,
		map: (wire: Wire) => GoAuthResult<T> = (w) => ok(w.body as T),
	): Promise<GoAuthResult<T>> {
		const res = await send(path, method, body);
		if (!res.success) return fail(res.error);
		const wire = res.data;
		// Server answers CodeTOTPRequired with HTTP 200 and an error body.
		if (
			isRecord(wire.body) &&
			typeof wire.body.code === "string" &&
			wire.body.message !== undefined
		) {
			return fail(toError(wire));
		}
		return map(wire);
	}

	const noContent = (): GoAuthResult<null> => ok(null);

	async function ceremony<T>(run: () => Promise<GoAuthResult<T>>): Promise<GoAuthResult<T>> {
		if (!isPasskeySupported()) {
			return fail({ code: GO_ERROR_PASSKEY_UNSUPPORTED, message: "", status: 0 });
		}
		try {
			return await run();
		} catch (err) {
			if (err instanceof DOMException && err.name === "NotAllowedError") {
				return fail({ code: GO_ERROR_PASSKEY_CANCELLED, message: err.message, status: 0 });
			}
			return fail({
				code: GO_ERROR_PASSKEY_UNSUPPORTED,
				message: err instanceof Error ? err.message : "",
				status: 0,
			});
		}
	}

	return {
		login: (input) =>
			call<LoginResult>("/email-password/signin", "POST", input, (w) => {
				const step = isRecord(w.body) ? w.body.step : undefined;
				return ok<LoginResult>({ status: step === "totp_required" ? "mfa_required" : "ok" });
			}),
		signup: (input) =>
			call("/email-password/signup", "POST", input, () => ok({ ok: true as const })),
		logout: () => call("/sessions/current", "DELETE", undefined, noContent),
		forgotPassword: (email) =>
			call("/email-password/forgot", "POST", { email }, (w) =>
				ok({ sent: isRecord(w.body) && w.body.sent === true }),
			),
		resetPassword: (input) =>
			call("/email-password/reset", "POST", input, () => ok({ ok: true as const })),
		session: {
			get: () => call<GoUser>("/me", "GET"),
			revokeCurrent: () => call("/sessions/current", "DELETE", undefined, noContent),
		},
		passkeys: {
			isSupported: isPasskeySupported,
			register: (name) =>
				ceremony(async () => {
					const begin = await call<CreationOptionsJSON>("/webauthn/register/begin", "POST");
					if (!begin.success) return fail(begin.error);
					const cred = await navigator.credentials.create({
						publicKey: creationOptionsFromJSON(begin.data),
					});
					if (!(cred instanceof PublicKeyCredential)) {
						return fail({ code: GO_ERROR_PASSKEY_CANCELLED, message: "", status: 0 });
					}
					const query = name ? `?name=${encodeURIComponent(name)}` : "";
					return call<PasskeyCredential>(
						`/webauthn/register/finish${query}`,
						"POST",
						attestationToJSON(cred),
					);
				}),
			login: () =>
				ceremony(async () => {
					const begin = await call<RequestOptionsJSON>("/webauthn/login/begin", "POST");
					if (!begin.success) return fail(begin.error);
					const cred = await navigator.credentials.get({
						publicKey: requestOptionsFromJSON(begin.data),
					});
					if (!(cred instanceof PublicKeyCredential)) {
						return fail({ code: GO_ERROR_PASSKEY_CANCELLED, message: "", status: 0 });
					}
					return call("/webauthn/login/finish", "POST", assertionToJSON(cred), () =>
						ok({ ok: true as const }),
					);
				}),
			list: () => call<PasskeyCredential[]>("/webauthn/credentials", "GET"),
			remove: (id) =>
				call(`/webauthn/credentials/${encodeURIComponent(id)}`, "DELETE", undefined, noContent),
		},
		totp: {
			enrollBegin: () => call<TotpEnrollment>("/totp/enroll/begin", "POST"),
			enrollFinish: (input) =>
				call<{ recoveryCodes: string[] }>("/totp/enroll/finish", "POST", input),
			verify: (code) => call("/totp/verify", "POST", { code }, () => ok({ ok: true as const })),
			recovery: (code) => call("/totp/recovery", "POST", { code }, () => ok({ ok: true as const })),
			disable: () => call("/totp/", "DELETE", undefined, noContent),
		},
	};
}
