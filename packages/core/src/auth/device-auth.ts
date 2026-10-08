/**
 * OAuth Device Authorization Grant (RFC 8628) for TheAuth.
 *
 * Built for CLIs, TVs and headless agents: the device asks for a short code,
 * a human approves it in a browser where they are already signed in, and the
 * device polls until it receives a token.
 *
 * Security properties:
 * - The device code is stored only as a SHA-256 hash.
 * - The approval endpoint takes the user from an authenticated session
 *   (`resolveUser` or the plugin's session), never from the request body.
 * - Guessing user codes is limited per approving user.
 * - `slow_down` is tracked in storage, so it holds across instances.
 * - A granted device code can be exchanged for a token exactly once.
 *
 * State lives in a `SecondaryStorage` (memory by default).
 *
 * @example
 * ```typescript
 * const deviceAuth = createDeviceAuthModule({
 *   verificationUri: 'https://example.com/device',
 *   resolveUser: async (req) => myApp.currentUser(req),
 *   issueToken: async (userId) => ({ accessToken: await mint(userId), expiresIn: 3600 }),
 * });
 * const res = await deviceAuth.handleRequest(request);
 * ```
 */

import { randomBytes, sha256, toHex } from "../crypto/web-crypto.js";
import type { TheAuthPlugin } from "../plugin/types.js";
import { memoryStorage } from "../storage/memory.js";
import type { SecondaryStorage } from "../storage/types.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export const DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

/** Credential handed to the device once the user approves. */
export interface DeviceTokenGrant {
	accessToken: string;
	tokenType?: string;
	/** Seconds until the access token expires. */
	expiresIn?: number;
	refreshToken?: string;
}

export interface DeviceGrantContext {
	clientId?: string;
	scope?: string;
}

export interface DeviceAuthConfig {
	/** Code length for the human-readable user code segment (default: 4, produces "XXXX-XXXX") */
	codeLength?: number;
	/** Code expiry in seconds (default: 900 = 15 min) */
	codeExpirySeconds?: number;
	/** Polling interval in seconds (default: 5) */
	pollIntervalSeconds?: number;
	/** Verification URL shown to user */
	verificationUri: string;
	/** Where grants live. Default: process memory. The plugin wires `secondaryStorage.deviceCodes`. */
	storage?: SecondaryStorage;
	/**
	 * Resolve the signed-in user for `POST /auth/device/authorize`. Required for
	 * `handleRequest` to accept approvals; without it the endpoint answers 401.
	 * The user id is never read from the request body.
	 */
	resolveUser?: (request: Request) => Promise<{ id: string } | null>;
	/** Mint the credential returned to the device after approval. */
	issueToken?: (userId: string, context: DeviceGrantContext) => Promise<DeviceTokenGrant>;
	/** Wrong user codes one approving user may try per window (default: 5). */
	userCodeAttemptLimit?: number;
	/** Window for the attempt limit, seconds (default: 900). */
	userCodeAttemptWindowSeconds?: number;
	/**
	 * Origins allowed to call the approval endpoint from a browser, in addition
	 * to the origin of `verificationUri`. Requests with a different `Origin`
	 * header are refused, which blocks cross-site approval (CSRF).
	 */
	trustedOrigins?: string[];
	/** Called after approve / deny / token issue. Wire it to your audit log. */
	onEvent?: (event: DeviceAuthEvent) => void | Promise<void>;
}

export interface DeviceAuthEvent {
	type: "device.code_issued" | "device.approved" | "device.denied" | "device.token_issued";
	userId?: string;
	clientId?: string;
}

export interface DeviceCodeRequest {
	clientId?: string;
	scope?: string;
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
	requestCode(request?: DeviceCodeRequest): Promise<DeviceCodeResponse>;
	/** Check if user has authorized (does not consume the grant) */
	checkAuthorization(deviceCode: string): Promise<DeviceAuthStatus>;
	/** Approve a user code as `userId`. Callers must have authenticated `userId` themselves. */
	authorize(userCode: string, userId: string): Promise<void>;
	/** Deny a user code. Pass the acting user id so failed guesses are rate limited per user. */
	deny(userCode: string, actorId?: string): Promise<void>;
	/**
	 * Handle the three device endpoints. Returns null for other paths.
	 * `opts.user` overrides `config.resolveUser` (the plugin passes its session user).
	 */
	handleRequest(
		request: Request,
		opts?: { user?: { id: string } | null },
	): Promise<Response | null>;
}

export class DeviceAuthError extends Error {
	readonly code: "invalid_user_code" | "expired" | "already_handled" | "too_many_attempts";
	constructor(code: DeviceAuthError["code"], message: string) {
		super(message);
		this.name = "DeviceAuthError";
		this.code = code;
	}
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

type GrantState = "pending" | "authorized" | "denied";

interface StoredGrant {
	state: GrantState;
	userCodeHash: string;
	expiresAt: number;
	interval: number;
	userId?: string;
	clientId?: string;
	scope?: string;
}

const DEFAULT_CODE_LENGTH = 4;
const DEFAULT_CODE_EXPIRY_SECONDS = 900;
const DEFAULT_POLL_INTERVAL_SECONDS = 5;
const DEFAULT_ATTEMPT_LIMIT = 5;
const DEFAULT_ATTEMPT_WINDOW_SECONDS = 900;
/** RFC 8628 section 3.5: add 5 seconds to the interval on slow_down. */
const SLOW_DOWN_STEP_SECONDS = 5;
const USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ"; // consonants only, avoids ambiguous chars

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			"Content-Type": "application/json",
			"Cache-Control": "no-store",
			Pragma: "no-cache",
		},
	});
}

function oauthError(error: string, description: string, status = 400, extra?: object): Response {
	return json({ error, error_description: description, ...extra }, status);
}

/** Read a JSON or form-encoded body into a flat string map. */
async function parseBody(request: Request): Promise<Record<string, unknown>> {
	try {
		const type = request.headers.get("content-type") ?? "";
		if (type.includes("application/x-www-form-urlencoded")) {
			return Object.fromEntries(new URLSearchParams(await request.text()));
		}
		const parsed: unknown = await request.json();
		return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
	} catch {
		return {};
	}
}

function str(value: unknown, max = 256): string | undefined {
	return typeof value === "string" && value.length > 0 ? value.slice(0, max) : undefined;
}

function generateDeviceCode(): string {
	return toHex(randomBytes(32));
}

/** "XXXX-XXXX" from a consonant-only alphabet (no vowels, no look-alikes). */
function generateUserCode(segmentLength: number): string {
	const total = segmentLength * 2;
	// Rejection sampling: drop bytes in the biased tail so each letter is equally likely.
	const limit = 256 - (256 % USER_CODE_ALPHABET.length);
	const chars: string[] = [];
	while (chars.length < total) {
		for (const byte of randomBytes(total * 2)) {
			if (byte >= limit) continue;
			chars.push(USER_CODE_ALPHABET[byte % USER_CODE_ALPHABET.length] ?? "B");
			if (chars.length === total) break;
		}
	}
	return `${chars.slice(0, segmentLength).join("")}-${chars.slice(segmentLength).join("")}`;
}

function normaliseUserCode(raw: string): string {
	return raw.trim().toUpperCase().replace(/[\s-]/g, "");
}

function buildCompleteUri(base: string, userCode: string): string {
	try {
		const url = new URL(base);
		url.searchParams.set("user_code", userCode);
		return url.toString();
	} catch {
		return `${base}?user_code=${encodeURIComponent(userCode)}`;
	}
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createDeviceAuthModule(config: DeviceAuthConfig): DeviceAuthModule {
	const segmentLength = config.codeLength ?? DEFAULT_CODE_LENGTH;
	const codeExpirySeconds = config.codeExpirySeconds ?? DEFAULT_CODE_EXPIRY_SECONDS;
	const baseInterval = config.pollIntervalSeconds ?? DEFAULT_POLL_INTERVAL_SECONDS;
	const attemptLimit = config.userCodeAttemptLimit ?? DEFAULT_ATTEMPT_LIMIT;
	const attemptWindow = config.userCodeAttemptWindowSeconds ?? DEFAULT_ATTEMPT_WINDOW_SECONDS;
	const storage = config.storage ?? memoryStorage();

	let verificationOrigin: string | null = null;
	try {
		verificationOrigin = new URL(config.verificationUri).origin;
	} catch {
		verificationOrigin = null;
	}
	const allowedOrigins = new Set([
		...(verificationOrigin ? [verificationOrigin] : []),
		...(config.trustedOrigins ?? []),
	]);

	const deviceKey = (hash: string) => `device:${hash}`;
	const userKey = (hash: string) => `user:${hash}`;

	async function emit(event: DeviceAuthEvent): Promise<void> {
		try {
			await config.onEvent?.(event);
		} catch {
			// Audit sinks must never break the auth flow.
		}
	}

	async function load(deviceHash: string): Promise<StoredGrant | null> {
		const raw = await storage.get(deviceKey(deviceHash));
		if (!raw) return null;
		try {
			const grant = JSON.parse(raw) as StoredGrant;
			return grant.expiresAt > Date.now() ? grant : null;
		} catch {
			return null;
		}
	}

	async function save(deviceHash: string, grant: StoredGrant): Promise<void> {
		const ttl = Math.max(Math.ceil((grant.expiresAt - Date.now()) / 1000), 1);
		await storage.set(deviceKey(deviceHash), JSON.stringify(grant), ttl);
	}

	async function destroy(deviceHash: string, grant: StoredGrant): Promise<void> {
		await storage.delete(deviceKey(deviceHash));
		await storage.delete(userKey(grant.userCodeHash));
	}

	/** Find the pending grant for a user code, enforcing the per-user attempt limit. */
	async function lookupByUserCode(
		userCode: string,
		actorId: string,
	): Promise<{ deviceHash: string; grant: StoredGrant }> {
		const attemptsKey = `attempts:${actorId}`;
		const used = Number.parseInt((await storage.get(attemptsKey)) ?? "0", 10);
		if (used >= attemptLimit) {
			throw new DeviceAuthError("too_many_attempts", "Too many incorrect codes, try again later");
		}

		const userHash = await sha256(normaliseUserCode(userCode));
		const deviceHash = await storage.get(userKey(userHash));
		const grant = deviceHash ? await load(deviceHash) : null;
		if (!deviceHash || !grant) {
			// Only misses count: a valid code never burns the budget.
			await storage.incr(attemptsKey, attemptWindow);
			throw new DeviceAuthError("invalid_user_code", "User code not found or expired");
		}
		return { deviceHash, grant };
	}

	async function requestCode(request: DeviceCodeRequest = {}): Promise<DeviceCodeResponse> {
		const deviceCode = generateDeviceCode();
		const userCode = generateUserCode(segmentLength);
		const deviceHash = await sha256(deviceCode);
		const userCodeHash = await sha256(normaliseUserCode(userCode));

		const grant: StoredGrant = {
			state: "pending",
			userCodeHash,
			expiresAt: Date.now() + codeExpirySeconds * 1000,
			interval: baseInterval,
			clientId: request.clientId,
			scope: request.scope,
		};
		await save(deviceHash, grant);
		await storage.set(userKey(userCodeHash), deviceHash, codeExpirySeconds);
		await emit({ type: "device.code_issued", clientId: request.clientId });

		return {
			deviceCode,
			userCode,
			verificationUri: config.verificationUri,
			verificationUriComplete: buildCompleteUri(config.verificationUri, userCode),
			expiresIn: codeExpirySeconds,
			interval: baseInterval,
		};
	}

	async function checkAuthorization(deviceCode: string): Promise<DeviceAuthStatus> {
		const grant = await load(await sha256(deviceCode));
		if (!grant) return { status: "expired" };
		if (grant.state === "authorized" && grant.userId) {
			return { status: "authorized", userId: grant.userId };
		}
		if (grant.state === "denied") return { status: "denied" };
		return { status: "pending" };
	}

	async function resolve(
		userCode: string,
		actorId: string,
		next: GrantState,
		userId?: string,
	): Promise<StoredGrant> {
		const { deviceHash, grant } = await lookupByUserCode(userCode, actorId);
		if (grant.state !== "pending") {
			throw new DeviceAuthError("already_handled", `Device code already ${grant.state}`);
		}
		grant.state = next;
		grant.userId = userId;
		await save(deviceHash, grant);
		return grant;
	}

	async function authorize(userCode: string, userId: string): Promise<void> {
		const grant = await resolve(userCode, userId, "authorized", userId);
		await emit({ type: "device.approved", userId, clientId: grant.clientId });
	}

	async function deny(userCode: string, actorId = "anonymous"): Promise<void> {
		const grant = await resolve(userCode, actorId, "denied");
		await emit({
			type: "device.denied",
			userId: actorId === "anonymous" ? undefined : actorId,
			clientId: grant.clientId,
		});
	}

	// -- HTTP handlers -------------------------------------------------------

	async function handleCode(request: Request): Promise<Response> {
		const body = await parseBody(request);
		const res = await requestCode({ clientId: str(body.client_id), scope: str(body.scope, 512) });
		return json({
			device_code: res.deviceCode,
			user_code: res.userCode,
			verification_uri: res.verificationUri,
			verification_uri_complete: res.verificationUriComplete,
			expires_in: res.expiresIn,
			interval: res.interval,
		});
	}

	async function handleToken(request: Request): Promise<Response> {
		const body = await parseBody(request);
		const deviceCode = str(body.device_code, 512);
		const grantType = str(body.grant_type);
		if (grantType && grantType !== DEVICE_CODE_GRANT_TYPE) {
			return oauthError("unsupported_grant_type", `grant_type must be ${DEVICE_CODE_GRANT_TYPE}`);
		}
		if (!deviceCode) return oauthError("invalid_request", "Missing device_code");

		const deviceHash = await sha256(deviceCode);
		const grant = await load(deviceHash);
		if (!grant) return oauthError("expired_token", "The device code has expired");

		// slow_down: more than one poll inside the interval, tracked in storage.
		const windowSeconds = Math.max(grant.interval - 1, 1);
		const { count } = await storage.incr(`poll:${deviceHash}`, windowSeconds);
		if (count > 1) {
			grant.interval += SLOW_DOWN_STEP_SECONDS;
			await save(deviceHash, grant);
			return oauthError("slow_down", "Polling too frequently", 400, { interval: grant.interval });
		}

		if (grant.state === "pending") {
			return oauthError("authorization_pending", "The user has not yet authorized the device");
		}
		if (grant.state === "denied") {
			await destroy(deviceHash, grant);
			return oauthError("access_denied", "The user denied the authorization request");
		}

		// Authorized: only the first poller to claim the grant gets a token.
		const claim = await storage.incr(`claim:${deviceHash}`, codeExpirySeconds);
		if (claim.count > 1 || !grant.userId) {
			return oauthError("expired_token", "The device code has already been used");
		}
		await destroy(deviceHash, grant);

		const userId = grant.userId;
		const base = { authorized: true, user_id: userId };
		if (!config.issueToken) return json(base);

		const token = await config.issueToken(userId, { clientId: grant.clientId, scope: grant.scope });
		await emit({ type: "device.token_issued", userId, clientId: grant.clientId });
		return json({
			...base,
			access_token: token.accessToken,
			token_type: token.tokenType ?? "Bearer",
			...(token.expiresIn !== undefined ? { expires_in: token.expiresIn } : {}),
			...(token.refreshToken ? { refresh_token: token.refreshToken } : {}),
			...(grant.scope ? { scope: grant.scope } : {}),
		});
	}

	async function handleAuthorize(
		request: Request,
		opts: { user?: { id: string } | null },
	): Promise<Response> {
		// Cross-site approval would let an attacker bind a victim's session to
		// the attacker's device code. Browsers always send Origin on cross-site POSTs.
		const origin = request.headers.get("origin");
		if (origin && !allowedOrigins.has(origin)) {
			return oauthError("access_denied", "Cross-origin approval is not allowed", 403);
		}
		// JSON only: a non-simple content type forces a CORS preflight.
		if (!(request.headers.get("content-type") ?? "").includes("application/json")) {
			return oauthError("invalid_request", "Content-Type must be application/json");
		}

		const user =
			opts.user !== undefined
				? opts.user
				: config.resolveUser
					? await config.resolveUser(request)
					: null;
		if (!user) {
			return oauthError("login_required", "Sign in to approve this device", 401);
		}

		const body = await parseBody(request);
		const userCode = str(body.user_code, 64);
		const action = str(body.action) ?? "approve";
		if (!userCode) return oauthError("invalid_request", "Missing user_code");
		if (action !== "approve" && action !== "deny") {
			return oauthError("invalid_request", "action must be approve or deny");
		}

		try {
			if (action === "deny") {
				await deny(userCode, user.id);
				return json({ denied: true });
			}
			await authorize(userCode, user.id);
			return json({ authorized: true });
		} catch (err) {
			if (err instanceof DeviceAuthError) {
				const status = err.code === "too_many_attempts" ? 429 : 400;
				return oauthError("invalid_request", err.message, status);
			}
			return oauthError("server_error", "Authorization failed", 500);
		}
	}

	async function handleRequest(
		request: Request,
		opts: { user?: { id: string } | null } = {},
	): Promise<Response | null> {
		const { pathname } = new URL(request.url);
		if (request.method !== "POST") return null;
		if (pathname.endsWith("/auth/device/code")) return handleCode(request);
		if (pathname.endsWith("/auth/device/token")) return handleToken(request);
		if (pathname.endsWith("/auth/device/authorize")) return handleAuthorize(request, opts);
		return null;
	}

	return { requestCode, checkAuthorization, authorize, deny, handleRequest };
}

// ---------------------------------------------------------------------------
// Plugin factory
// ---------------------------------------------------------------------------

export type DeviceAuthPluginConfig = Omit<DeviceAuthConfig, "resolveUser">;

/**
 * Mount the device endpoints on TheAuth. Approval uses the signed-in session
 * user, state follows `secondaryStorage.deviceCodes`, and the device receives a
 * TheAuth session token when `auth.session` is configured.
 */
export function deviceAuth(config: DeviceAuthPluginConfig): TheAuthPlugin {
	return {
		id: "theauth-device-auth",

		async init(ctx): Promise<undefined> {
			const sessionManager = ctx.sessionManager;
			const mod = createDeviceAuthModule({
				...config,
				storage: config.storage ?? ctx.secondaryStorage?.for("deviceCodes"),
				issueToken:
					config.issueToken ??
					(sessionManager
						? async (userId, grant) => {
								const { session, token } = await sessionManager.create(userId, {
									source: "device",
									clientId: grant.clientId ?? null,
								});
								return {
									accessToken: token,
									expiresIn: Math.max(
										Math.floor((session.expiresAt.getTime() - Date.now()) / 1000),
										1,
									),
								};
							}
						: undefined),
			});

			const delegate = async (request: Request, user?: { id: string } | null): Promise<Response> =>
				(await mod.handleRequest(request, { user })) ??
				new Response(JSON.stringify({ error: "not_found" }), {
					status: 404,
					headers: { "Content-Type": "application/json" },
				});

			ctx.addEndpoint({
				method: "POST",
				path: "/auth/device/code",
				metadata: {
					description: "Request a device code and user code for the device authorization flow",
					rateLimit: { window: 60, max: 30 },
				},
				handler: (request) => delegate(request),
			});

			ctx.addEndpoint({
				method: "POST",
				path: "/auth/device/token",
				metadata: { description: "Poll for device authorization status (RFC 8628)" },
				handler: (request) => delegate(request),
			});

			ctx.addEndpoint({
				method: "POST",
				path: "/auth/device/authorize",
				metadata: {
					description: "Signed-in user approves or denies a device authorization request",
					rateLimit: { window: 60, max: 30 },
				},
				async handler(request, endpointCtx) {
					return delegate(request, await endpointCtx.getUser(request));
				},
			});

			return undefined;
		},
	};
}
