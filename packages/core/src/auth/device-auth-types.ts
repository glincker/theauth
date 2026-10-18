import type { SecondaryStorage } from "../storage/types.js";

export const DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

export interface DeviceTokenGrant {
	accessToken: string;
	tokenType?: string;
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
	verificationUri: string;
	/** Where grants live. Default: process memory. The plugin wires `secondaryStorage.deviceCodes`. */
	storage?: SecondaryStorage;
	/** Resolve the signed-in user for `POST /auth/device/authorize`. Required for `handleRequest` to accept approvals; without it the endpoint answers 401. The user id is never read from the request body. */
	resolveUser?: (request: Request) => Promise<{ id: string } | null>;
	/** Mint the credential returned to the device after approval. Throw a `SignInGateError` to answer the poll with a gate challenge instead. */
	issueToken?: (userId: string, context: DeviceGrantContext) => Promise<DeviceTokenGrant>;
	/** Wrong user codes one approving user may try per window (default: 5). */
	userCodeAttemptLimit?: number;
	/** Window for the attempt limit, seconds (default: 900). */
	userCodeAttemptWindowSeconds?: number;
	/**
	 * Origins allowed to call the approval endpoint from a browser, in addition to the origin of `verificationUri`. Requests with a different `Origin` header are refused, which blocks cross-site approval (CSRF).
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
	requestCode(request?: DeviceCodeRequest): Promise<DeviceCodeResponse>;
	/** Check if user has authorized (does not consume the grant) */
	checkAuthorization(deviceCode: string): Promise<DeviceAuthStatus>;
	/** Approve a user code as `userId`. Callers must have authenticated `userId` themselves. */
	authorize(userCode: string, userId: string): Promise<void>;
	/** Deny a user code. Pass the acting user id so failed guesses are rate limited per user. */
	deny(userCode: string, actorId?: string): Promise<void>;
	/** Handle the three device endpoints. Returns null for other paths. `opts.user` overrides `config.resolveUser` (the plugin passes its session user). */
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
