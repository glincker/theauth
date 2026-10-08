import type { TokenCacheOptions } from "./token-cache.js";
import { saveCredential, serverKey } from "./token-cache.js";

export const DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

export interface DeviceFlowPrompt {
	userCode: string;
	verificationUri: string;
	verificationUriComplete: string;
	expiresIn: number;
}

export interface DeviceFlowOptions {
	/** Base URL where TheAuth is mounted, for example `https://app.example.com/api/theauth`. */
	serverUrl: string;
	clientId?: string;
	scope?: string;
	/** Show the code to the user. Default writes to stderr. */
	onPrompt?: (prompt: DeviceFlowPrompt) => void | Promise<void>;
	/** Called after the prompt; use it to open a browser. Failures are ignored. */
	openBrowser?: (url: string) => void | Promise<void>;
	/** Persist the token with the credential cache. Default true. */
	save?: boolean;
	cache?: TokenCacheOptions;
	signal?: AbortSignal;
	/** Injected for tests. */
	fetch?: typeof fetch;
	sleep?: (ms: number) => Promise<void>;
}

export interface DeviceFlowResult {
	accessToken: string;
	tokenType: string;
	expiresIn?: number;
	userId?: string;
	refreshToken?: string;
}

export class DeviceFlowError extends Error {
	readonly code: "access_denied" | "expired_token" | "aborted" | "server_error" | "no_token";
	constructor(code: DeviceFlowError["code"], message: string) {
		super(message);
		this.name = "DeviceFlowError";
		this.code = code;
	}
}

interface CodeResponse {
	device_code: string;
	user_code: string;
	verification_uri: string;
	verification_uri_complete?: string;
	expires_in: number;
	interval?: number;
}

interface TokenResponse {
	access_token?: string;
	token_type?: string;
	expires_in?: number;
	user_id?: string;
	refresh_token?: string;
	error?: string;
	error_description?: string;
	interval?: number;
}

const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Run the RFC 8628 device flow against a TheAuth server: request a code, show
 * it, poll until the user approves, and (by default) save the token.
 *
 * Usable from any CLI or MCP client:
 *
 * ```ts
 * const { accessToken } = await loginWithDeviceFlow({ serverUrl: "https://app.example.com/api/theauth" });
 * ```
 */
export async function loginWithDeviceFlow(opts: DeviceFlowOptions): Promise<DeviceFlowResult> {
	const doFetch = opts.fetch ?? fetch;
	const sleep = opts.sleep ?? defaultSleep;
	const base = serverKey(opts.serverUrl);

	const codeRes = await doFetch(`${base}/auth/device/code`, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({ client_id: opts.clientId, scope: opts.scope }),
		signal: opts.signal,
	});
	if (!codeRes.ok) {
		throw new DeviceFlowError("server_error", `Device code request failed (${codeRes.status})`);
	}
	const code = (await codeRes.json()) as CodeResponse;

	const prompt: DeviceFlowPrompt = {
		userCode: code.user_code,
		verificationUri: code.verification_uri,
		verificationUriComplete: code.verification_uri_complete ?? code.verification_uri,
		expiresIn: code.expires_in,
	};
	if (opts.onPrompt) await opts.onPrompt(prompt);
	else {
		process.stderr.write(
			`\nOpen ${prompt.verificationUri} and enter the code: ${prompt.userCode}\n(or open ${prompt.verificationUriComplete})\n\n`,
		);
	}
	try {
		await opts.openBrowser?.(prompt.verificationUriComplete);
	} catch {
		// The code is already on screen; opening a browser is a convenience.
	}

	let interval = code.interval ?? 5;
	const deadline = Date.now() + code.expires_in * 1000;

	while (Date.now() < deadline) {
		if (opts.signal?.aborted) throw new DeviceFlowError("aborted", "Login cancelled");
		await sleep(interval * 1000);
		if (opts.signal?.aborted) throw new DeviceFlowError("aborted", "Login cancelled");

		const res = await doFetch(`${base}/auth/device/token`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ device_code: code.device_code, grant_type: DEVICE_GRANT_TYPE }),
			signal: opts.signal,
		});
		const body = (await res.json().catch(() => ({}))) as TokenResponse;

		if (res.ok && body.access_token) {
			const result: DeviceFlowResult = {
				accessToken: body.access_token,
				tokenType: body.token_type ?? "Bearer",
				expiresIn: body.expires_in,
				userId: body.user_id,
				refreshToken: body.refresh_token,
			};
			if (opts.save !== false) {
				await saveCredential(
					base,
					{
						accessToken: result.accessToken,
						tokenType: result.tokenType,
						expiresAt: result.expiresIn ? Date.now() + result.expiresIn * 1000 : undefined,
						userId: result.userId,
						savedAt: Date.now(),
					},
					opts.cache,
				);
			}
			return result;
		}
		if (res.ok) {
			throw new DeviceFlowError(
				"no_token",
				"Server approved the login but returned no access token. Configure auth.session or issueToken on the server.",
			);
		}

		switch (body.error) {
			case "authorization_pending":
				break;
			case "slow_down":
				interval = body.interval ?? interval + 5;
				break;
			case "access_denied":
				throw new DeviceFlowError("access_denied", "Login was denied in the browser");
			case "expired_token":
				throw new DeviceFlowError("expired_token", "The code expired before it was approved");
			default:
				throw new DeviceFlowError(
					"server_error",
					body.error_description ?? `Unexpected response (${res.status})`,
				);
		}
	}
	throw new DeviceFlowError("expired_token", "The code expired before it was approved");
}
