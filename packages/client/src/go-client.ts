import type {
	BootstrapStatus,
	DeviceCode,
	DeviceRequestInfo,
	DeviceToken,
	GoAgent,
	GoApiToken,
	GoAuthError,
	GoAuthResult,
	GoCurrentToken,
	GoDelegation,
	GoSession,
	GoUser,
	LoginResult,
	MintedApiToken,
	PasskeyCredential,
	RegisteredAgent,
	StepUpResult,
	TheAuthGoClient,
	TheAuthGoClientOptions,
	TotpEnrollment,
	TotpStatus,
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

const DEVICE_PENDING = "authorization_pending";
const DEVICE_SLOW_DOWN = "slow_down";
const DEVICE_EXPIRED = "expired_token";
const DEVICE_DEFAULT_INTERVAL_S = 5;
const DEVICE_SLOW_DOWN_STEP_S = 5;
const DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";
const SETUP_TOKEN_HEADER = "X-Setup-Token";

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
	if (isRecord(body) && typeof body.error === "string") {
		return {
			code: body.error,
			message: typeof body.error_description === "string" ? body.error_description : "",
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

	async function send(
		path: string,
		method: string,
		body?: unknown,
		extraHeaders?: Record<string, string>,
	): Promise<GoAuthResult<Wire>> {
		const doFetch = options.fetch ?? globalThis.fetch;
		let res: Response;
		try {
			const token = await options.getToken?.();
			res = await doFetch(`${prefix}${path}`, {
				method,
				credentials: token ? "omit" : (options.credentials ?? "include"),
				headers: {
					...(body === undefined ? {} : { "Content-Type": "application/json" }),
					...options.headers,
					...(token ? { Authorization: `Bearer ${token}` } : {}),
					...extraHeaders,
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
		extraHeaders?: Record<string, string>,
	): Promise<GoAuthResult<T>> {
		const res = await send(path, method, body, extraHeaders);
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

	const reasonQuery = (reason?: string) => (reason ? `?reason=${encodeURIComponent(reason)}` : "");

	const noContent = (): GoAuthResult<null> => ok(null);

	const field = (body: unknown, key: string): unknown => (isRecord(body) ? body[key] : undefined);
	const str = (v: unknown): string => (typeof v === "string" ? v : "");
	const num = (v: unknown): number => (typeof v === "number" ? v : 0);
	const strings = (v: unknown): string[] =>
		Array.isArray(v) ? v.filter((e): e is string => typeof e === "string") : [];

	const deviceToken = (deviceCode: string) =>
		call<DeviceToken>(
			"/device/token",
			"POST",
			{ grant_type: DEVICE_GRANT_TYPE, device_code: deviceCode },
			(w) =>
				ok({
					accessToken: str(field(w.body, "access_token")),
					tokenType: str(field(w.body, "token_type")),
					expiresIn: num(field(w.body, "expires_in")),
					scope: str(field(w.body, "scope")),
				}),
		);

	const deviceDecision = (action: string, userCode: string, abilities?: string[]) =>
		call(
			"/device/approve",
			"POST",
			{ action, user_code: userCode, ...(abilities ? { abilities } : {}) },
			noContent,
		);

	const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

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
		signup: ({ setupToken, ...creds }) =>
			call(
				"/email-password/signup",
				"POST",
				creds,
				() => ok({ ok: true as const }),
				setupToken ? { [SETUP_TOKEN_HEADER]: setupToken } : undefined,
			),
		changePassword: (input) => call("/password/change", "POST", input, noContent),
		bootstrap: {
			status: () =>
				call<BootstrapStatus>("/bootstrap/status", "GET", undefined, (w) =>
					ok({ needsSetup: field(w.body, "needsSetup") === true }),
				),
		},
		stepUp: {
			verify: (proof) => call<StepUpResult>("/step-up", "POST", proof),
			passkey: () =>
				ceremony(async () => {
					const begin = await call<{ options: RequestOptionsJSON; challenge: string }>(
						"/step-up/passkey/begin",
						"POST",
					);
					if (!begin.success) return fail(begin.error);
					const cred = await navigator.credentials.get({
						publicKey: requestOptionsFromJSON(begin.data.options),
					});
					if (!(cred instanceof PublicKeyCredential)) {
						return fail({ code: GO_ERROR_PASSKEY_CANCELLED, message: "", status: 0 });
					}
					return call<StepUpResult>("/step-up", "POST", {
						method: "passkey",
						challenge: begin.data.challenge,
						assertion: assertionToJSON(cred),
					});
				}),
		},
		apiTokens: {
			list: (opts = {}) => {
				const q = new URLSearchParams();
				if (opts.all) q.set("all", "true");
				if (opts.ownerId) q.set("owner_id", opts.ownerId);
				const qs = q.toString();
				return call<GoApiToken[]>(`/tokens/${qs ? `?${qs}` : ""}`, "GET", undefined, (w) =>
					ok(
						Array.isArray(field(w.body, "tokens")) ? (field(w.body, "tokens") as GoApiToken[]) : [],
					),
				);
			},
			mint: ({ expiresIn, serviceAccount, ownerId, agentName, ...rest }) =>
				call<MintedApiToken>("/tokens/", "POST", {
					...rest,
					...(agentName ? { agent_name: agentName } : {}),
					...(expiresIn === undefined ? {} : { expires_in: expiresIn }),
					...(serviceAccount ? { service_account: true } : {}),
					...(ownerId ? { owner_id: ownerId } : {}),
				}),
			revoke: (id) => call(`/tokens/${encodeURIComponent(id)}`, "DELETE", undefined, noContent),
			current: () => call<GoCurrentToken>("/tokens/current", "GET"),
			revokeCurrent: () => call("/tokens/current", "DELETE", undefined, noContent),
		},
		agents: {
			list: () =>
				call<GoAgent[]>("/account/agents", "GET", undefined, (w) => {
					const list = field(w.body, "agents");
					return ok(Array.isArray(list) ? (list as GoAgent[]) : []);
				}),
			register: (input) => call<RegisteredAgent>("/account/agents", "POST", input),
			revoke: (id, reason) =>
				call(
					`/account/agents/${encodeURIComponent(id)}${reasonQuery(reason)}`,
					"DELETE",
					undefined,
					noContent,
				),
		},
		delegations: {
			list: () =>
				call<GoDelegation[]>("/account/delegations", "GET", undefined, (w) => {
					const list = field(w.body, "delegations");
					return ok(Array.isArray(list) ? (list as GoDelegation[]) : []);
				}),
			grant: (input) => call<GoDelegation>("/account/delegations", "POST", input),
			revoke: (id, reason) =>
				call(
					`/account/delegations/${encodeURIComponent(id)}/revoke${reasonQuery(reason)}`,
					"POST",
					undefined,
					noContent,
				),
		},
		device: {
			code: (input = {}) =>
				call<DeviceCode>(
					"/device/code",
					"POST",
					{
						...(input.clientName ? { client_name: input.clientName } : {}),
						...(input.abilities ? { abilities: input.abilities } : {}),
					},
					(w) =>
						ok({
							deviceCode: str(field(w.body, "device_code")),
							userCode: str(field(w.body, "user_code")),
							verificationUri: str(field(w.body, "verification_uri")),
							verificationUriComplete: str(field(w.body, "verification_uri_complete")),
							expiresIn: num(field(w.body, "expires_in")),
							interval: num(field(w.body, "interval")),
						}),
				),
			token: deviceToken,
			poll: async ({ deviceCode, interval, expiresIn, signal, sleep = defaultSleep }) => {
				let wait = interval ?? DEVICE_DEFAULT_INTERVAL_S;
				let elapsed = 0;
				for (;;) {
					const res = await deviceToken(deviceCode);
					if (res.success) return res;
					if (res.error.code === DEVICE_SLOW_DOWN) wait += DEVICE_SLOW_DOWN_STEP_S;
					else if (res.error.code !== DEVICE_PENDING) return res;
					if (signal?.aborted)
						return fail({ code: GO_ERROR_NETWORK, message: "aborted", status: 0 });
					if (expiresIn !== undefined && elapsed + wait > expiresIn) {
						return fail({ code: DEVICE_EXPIRED, message: "", status: 400 });
					}
					await sleep(wait * 1000);
					elapsed += wait;
				}
			},
			info: (userCode) =>
				call<DeviceRequestInfo>(
					"/device/approve",
					"POST",
					{ action: "info", user_code: userCode },
					(w) =>
						ok({
							clientName: str(field(w.body, "client_name")),
							abilities: strings(field(w.body, "abilities")),
							requesterIp: str(field(w.body, "requester_ip")),
							requesterUserAgent: str(field(w.body, "requester_user_agent")),
							expiresAt: str(field(w.body, "expires_at")),
						}),
				),
			approve: (userCode, abilities) => deviceDecision("approve", userCode, abilities),
			deny: (userCode) => deviceDecision("deny", userCode),
		},
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
			list: () =>
				call<GoSession[]>("/sessions", "GET", undefined, (w) => {
					const list = field(w.body, "sessions");
					return ok(Array.isArray(list) ? (list as GoSession[]) : []);
				}),
			revoke: (id) => call(`/sessions/${encodeURIComponent(id)}`, "DELETE", undefined, noContent),
			revokeOthers: () =>
				call("/sessions/revoke-others", "POST", undefined, (w) =>
					ok({ revoked: num(field(w.body, "revoked")) }),
				),
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
			rename: (id, name) =>
				call(`/webauthn/credentials/${encodeURIComponent(id)}`, "PATCH", { name }, noContent),
		},
		totp: {
			enrollBegin: () => call<TotpEnrollment>("/totp/enroll/begin", "POST"),
			enrollFinish: (input) =>
				call<{ recoveryCodes: string[] }>("/totp/enroll/finish", "POST", input),
			verify: (code) => call("/totp/verify", "POST", { code }, () => ok({ ok: true as const })),
			recovery: (code) => call("/totp/recovery", "POST", { code }, () => ok({ ok: true as const })),
			disable: () => call("/totp/", "DELETE", undefined, noContent),
			status: () => call<TotpStatus>("/totp/", "GET"),
			regenerateRecoveryCodes: () =>
				call<{ recoveryCodes: string[] }>("/totp/recovery-codes", "POST"),
		},
	};
}
