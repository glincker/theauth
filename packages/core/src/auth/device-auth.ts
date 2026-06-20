/**
 * OAuth Device Authorization Grant (RFC 8628) for TheAuth.
 *
 * Supports TVs, CLI tools, smart displays, and any device where the user
 * cannot easily type a URL or complete an interactive login flow. The device
 * requests a short code, the user approves on a secondary device (phone /
 * browser), and the original device polls until authorization is granted.
 *
 * @example
 * ```typescript
 * const deviceAuth = createDeviceAuthModule({
 *   verificationUri: 'https://example.com/device',
 * });
 *
 * // 1. CLI tool requests codes
 * const { userCode, verificationUri } = await deviceAuth.requestCode();
 * console.log(`Visit ${verificationUri} and enter: ${userCode}`);
 *
 * // 2. Poll from CLI
 * const status = await deviceAuth.checkAuthorization(deviceCode);
 *
 * // 3. User approves on browser after logging in
 * await deviceAuth.authorize(userCode, userId);
 * ```
 */

import { randomBytes, toHex } from "../crypto/web-crypto.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface DeviceAuthConfig {
	/** Code length for the human-readable user code segment (default: 4, produces "XXXX-XXXX") */
	codeLength?: number;
	/** Code expiry in seconds (default: 900 = 15 min) */
	codeExpirySeconds?: number;
	/** Polling interval in seconds (default: 5) */
	pollIntervalSeconds?: number;
	/** Verification URL shown to user */
	verificationUri: string;
}

export interface DeviceCodeResponse {
	deviceCode: string;
	userCode: string;
	verificationUri: string;
	verificationUriComplete: string;
	expiresIn: number;
	interval: number;
}

export type DeviceAuthStatus =
	| { status: "pending" }
	| { status: "authorized"; userId: string }
	| { status: "expired" }
	| { status: "denied" };

export interface DeviceAuthModule {
	/** Start device auth flow: returns device_code, user_code, verification_uri */
	requestCode(): Promise<DeviceCodeResponse>;
	/** Check if user has authorized (called by polling device) */
	checkAuthorization(deviceCode: string): Promise<DeviceAuthStatus>;
	/** Authorize a device (called after user logs in on phone/browser) */
	authorize(userCode: string, userId: string): Promise<void>;
	/** Deny a device code (user explicitly rejects) */
	deny(userCode: string): Promise<void>;
	/** Handle HTTP requests for the device auth endpoints */
	handleRequest(request: Request): Promise<Response | null>;
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

type DeviceGrantState = "pending" | "authorized" | "denied";

interface DeviceGrant {
	deviceCode: string;
	userCode: string;
	expiresAt: number;
	state: DeviceGrantState;
	userId?: string;
	/** Tracks last poll time for slow_down detection */
	lastPolledAt?: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_CODE_LENGTH = 4;
const DEFAULT_CODE_EXPIRY_SECONDS = 900;
const DEFAULT_POLL_INTERVAL_SECONDS = 5;
const USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ"; // consonants only, avoids ambiguous chars
// Minimum ms between polls before we ask the client to slow down
const SLOW_DOWN_THRESHOLD_MS = 4_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

async function parseBody(request: Request): Promise<Record<string, unknown>> {
	try {
		return (await request.json()) as Record<string, unknown>;
	} catch {
		return {};
	}
}

function generateDeviceCode(): string {
	return toHex(randomBytes(32));
}

/**
 * Generate a human-readable user code of the form "XXXX-XXXX".
 * Uses a consonant-only alphabet to avoid ambiguous characters and
 * accidental profanity.
 */
function generateUserCode(segmentLength: number): string {
	const bytes = randomBytes(segmentLength * 2);
	const chars: string[] = [];
	for (let i = 0; i < segmentLength * 2; i++) {
		const byte = bytes[i] ?? 0;
		const char = USER_CODE_ALPHABET[byte % USER_CODE_ALPHABET.length] ?? "B";
		chars.push(char);
	}
	return `${chars.slice(0, segmentLength).join("")}-${chars.slice(segmentLength).join("")}`;
}

function normaliseUserCode(raw: string): string {
	return raw.trim().toUpperCase().replace(/[\s-]/g, "");
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createDeviceAuthModule(config: DeviceAuthConfig): DeviceAuthModule {
	const segmentLength = config.codeLength ?? DEFAULT_CODE_LENGTH;
	const codeExpiryMs = (config.codeExpirySeconds ?? DEFAULT_CODE_EXPIRY_SECONDS) * 1000;
	const pollIntervalSeconds = config.pollIntervalSeconds ?? DEFAULT_POLL_INTERVAL_SECONDS;

	// In-memory grant store: deviceCode -> DeviceGrant
	const grantsByDevice = new Map<string, DeviceGrant>();
	// Secondary index: normalised userCode -> deviceCode
	const deviceByUserCode = new Map<string, string>();

	function purgeExpired(): void {
		const now = Date.now();
		for (const [deviceCode, grant] of grantsByDevice) {
			if (grant.expiresAt <= now) {
				deviceByUserCode.delete(normaliseUserCode(grant.userCode));
				grantsByDevice.delete(deviceCode);
			}
		}
	}

	async function requestCode(): Promise<DeviceCodeResponse> {
		purgeExpired();

		const deviceCode = generateDeviceCode();
		const userCode = generateUserCode(segmentLength);
		const expiresAt = Date.now() + codeExpiryMs;

		const grant: DeviceGrant = {
			deviceCode,
			userCode,
			expiresAt,
			state: "pending",
		};

		grantsByDevice.set(deviceCode, grant);
		deviceByUserCode.set(normaliseUserCode(userCode), deviceCode);

		const verificationUriComplete = `${config.verificationUri}?user_code=${encodeURIComponent(userCode)}`;

		return {
			deviceCode,
			userCode,
			verificationUri: config.verificationUri,
			verificationUriComplete,
			expiresIn: Math.floor(codeExpiryMs / 1000),
			interval: pollIntervalSeconds,
		};
	}

	async function checkAuthorization(deviceCode: string): Promise<DeviceAuthStatus> {
		purgeExpired();

		const grant = grantsByDevice.get(deviceCode);

		if (!grant) {
			// Code was never issued or already purged after expiry
			return { status: "expired" };
		}

		if (grant.expiresAt <= Date.now()) {
			deviceByUserCode.delete(normaliseUserCode(grant.userCode));
			grantsByDevice.delete(deviceCode);
			return { status: "expired" };
		}

		const now = Date.now();

		if (grant.state === "authorized" && grant.userId) {
			return { status: "authorized", userId: grant.userId };
		}

		if (grant.state === "denied") {
			return { status: "denied" };
		}

		// Update last polled time (for slow_down detection upstream)
		grant.lastPolledAt = now;

		return { status: "pending" };
	}

	async function authorize(userCode: string, userId: string): Promise<void> {
		purgeExpired();

		const normalised = normaliseUserCode(userCode);
		const deviceCode = deviceByUserCode.get(normalised);

		if (!deviceCode) {
			throw new Error("User code not found or expired");
		}

		const grant = grantsByDevice.get(deviceCode);
		if (!grant || grant.expiresAt <= Date.now()) {
			deviceByUserCode.delete(normalised);
			if (deviceCode) grantsByDevice.delete(deviceCode);
			throw new Error("Device code expired");
		}

		if (grant.state !== "pending") {
			throw new Error(`Device code already ${grant.state}`);
		}

		grant.state = "authorized";
		grant.userId = userId;
	}

	async function deny(userCode: string): Promise<void> {
		purgeExpired();

		const normalised = normaliseUserCode(userCode);
		const deviceCode = deviceByUserCode.get(normalised);

		if (!deviceCode) {
			throw new Error("User code not found or expired");
		}

		const grant = grantsByDevice.get(deviceCode);
		if (!grant || grant.expiresAt <= Date.now()) {
			deviceByUserCode.delete(normalised);
			if (deviceCode) grantsByDevice.delete(deviceCode);
			throw new Error("Device code expired");
		}

		if (grant.state !== "pending") {
			throw new Error(`Device code already ${grant.state}`);
		}

		grant.state = "denied";
	}

	async function handleRequest(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		const { method, pathname } = { method: request.method, pathname: url.pathname };

		// POST /auth/device/code
		if (method === "POST" && pathname.endsWith("/auth/device/code")) {
			const response = await requestCode();
			return jsonResponse({
				device_code: response.deviceCode,
				user_code: response.userCode,
				verification_uri: response.verificationUri,
				verification_uri_complete: response.verificationUriComplete,
				expires_in: response.expiresIn,
				interval: response.interval,
			});
		}

		// POST /auth/device/token  — polling endpoint (RFC 8628 §3.4)
		if (method === "POST" && pathname.endsWith("/auth/device/token")) {
			const body = await parseBody(request);
			const deviceCode = typeof body.device_code === "string" ? body.device_code : null;

			if (!deviceCode) {
				return jsonResponse(
					{ error: "invalid_request", error_description: "Missing device_code" },
					400,
				);
			}

			// Slow-down detection
			const grant = grantsByDevice.get(deviceCode);
			if (grant?.lastPolledAt && Date.now() - grant.lastPolledAt < SLOW_DOWN_THRESHOLD_MS) {
				return jsonResponse(
					{
						error: "slow_down",
						error_description: "Polling too frequently",
						interval: pollIntervalSeconds + 5,
					},
					400,
				);
			}

			const status = await checkAuthorization(deviceCode);

			if (status.status === "authorized") {
				return jsonResponse({ authorized: true, user_id: status.userId });
			}

			if (status.status === "pending") {
				return jsonResponse(
					{
						error: "authorization_pending",
						error_description: "The user has not yet authorized the device",
					},
					400,
				);
			}

			if (status.status === "denied") {
				return jsonResponse(
					{
						error: "access_denied",
						error_description: "The user denied the authorization request",
					},
					400,
				);
			}

			// expired
			return jsonResponse(
				{
					error: "expired_token",
					error_description: "The device code has expired",
				},
				400,
			);
		}

		// POST /auth/device/authorize — user approval (requires auth handled by caller)
		if (method === "POST" && pathname.endsWith("/auth/device/authorize")) {
			const body = await parseBody(request);
			const userCode = typeof body.user_code === "string" ? body.user_code : null;
			const userId = typeof body.user_id === "string" ? body.user_id : null;
			const action = typeof body.action === "string" ? body.action : "approve";

			if (!userCode || !userId) {
				return jsonResponse(
					{ error: "invalid_request", error_description: "Missing user_code or user_id" },
					400,
				);
			}

			try {
				if (action === "deny") {
					await deny(userCode);
					return jsonResponse({ denied: true });
				}
				await authorize(userCode, userId);
				return jsonResponse({ authorized: true });
			} catch (err) {
				return jsonResponse(
					{
						error: "invalid_request",
						error_description: err instanceof Error ? err.message : "Authorization failed",
					},
					400,
				);
			}
		}

		return null;
	}

	return { requestCode, checkAuthorization, authorize, deny, handleRequest };
}

// ---------------------------------------------------------------------------
// Plugin factory
// ---------------------------------------------------------------------------

import type { KavachPlugin } from "../plugin/types.js";

export function deviceAuth(config: DeviceAuthConfig): KavachPlugin {
	return {
		id: "kavach-device-auth",

		async init(ctx): Promise<undefined> {
			const mod = createDeviceAuthModule(config);

			// POST /auth/device/code
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/device/code",
				metadata: {
					description: "Request a device code and user code for the device authorization flow",
					rateLimit: { window: 60_000, max: 30 },
				},
				async handler(_request, _endpointCtx) {
					const response = await mod.requestCode();
					return new Response(
						JSON.stringify({
							device_code: response.deviceCode,
							user_code: response.userCode,
							verification_uri: response.verificationUri,
							verification_uri_complete: response.verificationUriComplete,
							expires_in: response.expiresIn,
							interval: response.interval,
						}),
						{ status: 200, headers: { "Content-Type": "application/json" } },
					);
				},
			});

			// POST /auth/device/token
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/device/token",
				metadata: {
					description: "Poll for device authorization status (RFC 8628)",
					rateLimit: { window: 10_000, max: 5 },
				},
				async handler(request, _endpointCtx) {
					let body: Record<string, unknown>;
					try {
						body = (await request.json()) as Record<string, unknown>;
					} catch {
						body = {};
					}

					const deviceCode = typeof body.device_code === "string" ? body.device_code : null;
					if (!deviceCode) {
						return new Response(
							JSON.stringify({
								error: "invalid_request",
								error_description: "Missing device_code",
							}),
							{ status: 400, headers: { "Content-Type": "application/json" } },
						);
					}

					const status = await mod.checkAuthorization(deviceCode);

					if (status.status === "authorized") {
						return new Response(JSON.stringify({ authorized: true, user_id: status.userId }), {
							status: 200,
							headers: { "Content-Type": "application/json" },
						});
					}

					const errorMap: Record<string, { error: string; error_description: string }> = {
						pending: {
							error: "authorization_pending",
							error_description: "The user has not yet authorized the device",
						},
						denied: {
							error: "access_denied",
							error_description: "The user denied the authorization request",
						},
						expired: {
							error: "expired_token",
							error_description: "The device code has expired",
						},
					};

					const errorBody = errorMap[status.status];
					return new Response(JSON.stringify(errorBody), {
						status: 400,
						headers: { "Content-Type": "application/json" },
					});
				},
			});

			// POST /auth/device/authorize
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/device/authorize",
				metadata: {
					requireAuth: true,
					description: "User approves or denies a device authorization request",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return new Response(JSON.stringify({ error: "Authentication required" }), {
							status: 401,
							headers: { "Content-Type": "application/json" },
						});
					}

					let body: Record<string, unknown>;
					try {
						body = (await request.json()) as Record<string, unknown>;
					} catch {
						body = {};
					}

					const userCode = typeof body.user_code === "string" ? body.user_code : null;
					const action = typeof body.action === "string" ? body.action : "approve";

					if (!userCode) {
						return new Response(
							JSON.stringify({
								error: "invalid_request",
								error_description: "Missing user_code",
							}),
							{ status: 400, headers: { "Content-Type": "application/json" } },
						);
					}

					try {
						if (action === "deny") {
							await mod.deny(userCode);
							return new Response(JSON.stringify({ denied: true }), {
								status: 200,
								headers: { "Content-Type": "application/json" },
							});
						}
						await mod.authorize(userCode, user.id);
						return new Response(JSON.stringify({ authorized: true }), {
							status: 200,
							headers: { "Content-Type": "application/json" },
						});
					} catch (err) {
						return new Response(
							JSON.stringify({
								error: "invalid_request",
								error_description: err instanceof Error ? err.message : "Authorization failed",
							}),
							{ status: 400, headers: { "Content-Type": "application/json" } },
						);
					}
				},
			});

			return undefined;
		},
	};
}
