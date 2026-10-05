export interface GoAuthError {
	code: string;
	message: string;
	status: number;
	/** Seconds from the Retry-After header, when the server sent one. */
	retryAfter?: number;
}

export type GoAuthResult<T> = { success: true; data: T } | { success: false; error: GoAuthError };

export interface GoUser {
	id: string;
	email: string;
	emailVerifiedAt?: string;
	name: string;
	avatarUrl: string;
	createdAt: string;
	updatedAt: string;
}

export type LoginResult = { status: "ok" } | { status: "mfa_required" };

export interface TotpEnrollment {
	secret: string;
	otpAuthUrl: string;
	enrollmentId: string;
}

export interface PasskeyCredential {
	id: string;
	userId: string;
	credentialId: string;
	signCount: number;
	transports: string[];
	aaguid: string;
	name: string;
	createdAt: string;
	lastUsedAt?: string;
}

export interface GoSession {
	id: string;
	deviceLabel: string;
	ipPrefix?: string;
	createdAt: string;
	lastSeenAt: string;
	expiresAt: string;
	current: boolean;
}

export type StepUpMethod = "password" | "totp" | "passkey";

export interface StepUpResult {
	elevatedUntil: string;
}

export type ApiTokenKind = "personal" | "agent";

export interface GoApiToken {
	id: string;
	ownerId: string;
	ownerKind: string;
	name: string;
	abilities: string[];
	hint: string;
	/** Empty or absent means personal. */
	kind?: ApiTokenKind | "";
	agentName?: string;
	/** The human whose abilities bound an agent token. */
	delegatedBy?: string;
	createdAt: string;
	expiresAt?: string;
	lastUsedAt?: string;
	revokedAt?: string;
}

export interface MintedApiToken extends GoApiToken {
	/** The raw secret. The server returns it once; it cannot be fetched again. */
	token: string;
}

export interface MintApiTokenInput {
	name: string;
	abilities: string[];
	kind?: ApiTokenKind;
	/** Names the agent or MCP client; used with kind "agent". */
	agentName?: string;
	/** Lifetime in seconds. */
	expiresIn?: number;
	/** Admin only: mint for a service account rather than the caller. */
	serviceAccount?: boolean;
	ownerId?: string;
}

export interface ListApiTokensOptions {
	/** Admin only: every token on the server. */
	all?: boolean;
	/** Admin only: tokens of one owner. */
	ownerId?: string;
}

export interface DeviceCodeInput {
	clientName?: string;
	abilities?: string[];
}

export interface DeviceCode {
	deviceCode: string;
	userCode: string;
	verificationUri: string;
	verificationUriComplete: string;
	/** Seconds until the device code expires. */
	expiresIn: number;
	/** Minimum seconds between token polls. */
	interval: number;
}

export interface DeviceToken {
	accessToken: string;
	tokenType: string;
	expiresIn: number;
	scope: string;
}

export interface DevicePollOptions {
	deviceCode: string;
	/** Seconds between polls. Defaults to 5, the RFC 8628 minimum. */
	interval?: number;
	/** Seconds after which polling gives up with expired_token. */
	expiresIn?: number;
	signal?: AbortSignal;
	/** Test seam: resolves after the given milliseconds. */
	sleep?: (ms: number) => Promise<void>;
}

export interface DeviceRequestInfo {
	clientName: string;
	abilities: string[];
	requesterIp: string;
	requesterUserAgent: string;
	expiresAt: string;
}

export interface BootstrapStatus {
	needsSetup: boolean;
}

export interface TotpStatus {
	enrolled: boolean;
	/** -1 when the storage backend cannot count them. */
	recoveryCodesRemaining: number;
}

export interface SignupInput {
	email: string;
	password: string;
	/** Sent as X-Setup-Token while the first-run bootstrap gate is open. */
	setupToken?: string;
}

export type StepUpProof =
	| { method: "password"; password: string }
	| { method: "totp"; code: string };

export interface TheAuthGoClientOptions {
	/** Origin of the auth server. Empty string means same origin. */
	baseUrl?: string;
	/** Where theauth-go is mounted. Defaults to "/auth". */
	basePath?: string;
	credentials?: RequestCredentials;
	headers?: Record<string, string>;
	fetch?: typeof fetch;
}

export interface TheAuthGoClient {
	login: (input: { email: string; password: string }) => Promise<GoAuthResult<LoginResult>>;
	signup: (input: SignupInput) => Promise<GoAuthResult<{ ok: true }>>;
	changePassword: (input: {
		currentPassword: string;
		newPassword: string;
	}) => Promise<GoAuthResult<null>>;
	bootstrap: { status: () => Promise<GoAuthResult<BootstrapStatus>> };
	stepUp: {
		verify: (proof: StepUpProof) => Promise<GoAuthResult<StepUpResult>>;
		passkey: () => Promise<GoAuthResult<StepUpResult>>;
	};
	apiTokens: {
		list: (options?: ListApiTokensOptions) => Promise<GoAuthResult<GoApiToken[]>>;
		mint: (input: MintApiTokenInput) => Promise<GoAuthResult<MintedApiToken>>;
		revoke: (id: string) => Promise<GoAuthResult<null>>;
	};
	device: {
		code: (input?: DeviceCodeInput) => Promise<GoAuthResult<DeviceCode>>;
		token: (deviceCode: string) => Promise<GoAuthResult<DeviceToken>>;
		poll: (options: DevicePollOptions) => Promise<GoAuthResult<DeviceToken>>;
		info: (userCode: string) => Promise<GoAuthResult<DeviceRequestInfo>>;
		approve: (userCode: string, abilities?: string[]) => Promise<GoAuthResult<null>>;
		deny: (userCode: string) => Promise<GoAuthResult<null>>;
	};
	logout: () => Promise<GoAuthResult<null>>;
	forgotPassword: (email: string) => Promise<GoAuthResult<{ sent: boolean }>>;
	resetPassword: (input: {
		token: string;
		newPassword: string;
	}) => Promise<GoAuthResult<{ ok: true }>>;
	session: {
		get: () => Promise<GoAuthResult<GoUser>>;
		revokeCurrent: () => Promise<GoAuthResult<null>>;
		list: () => Promise<GoAuthResult<GoSession[]>>;
		revoke: (id: string) => Promise<GoAuthResult<null>>;
		revokeOthers: () => Promise<GoAuthResult<{ revoked: number }>>;
	};
	passkeys: {
		isSupported: () => boolean;
		register: (name?: string) => Promise<GoAuthResult<PasskeyCredential>>;
		login: () => Promise<GoAuthResult<{ ok: true }>>;
		list: () => Promise<GoAuthResult<PasskeyCredential[]>>;
		remove: (id: string) => Promise<GoAuthResult<null>>;
		rename: (id: string, name: string) => Promise<GoAuthResult<null>>;
	};
	totp: {
		enrollBegin: () => Promise<GoAuthResult<TotpEnrollment>>;
		enrollFinish: (input: {
			enrollmentId: string;
			code: string;
		}) => Promise<GoAuthResult<{ recoveryCodes: string[] }>>;
		verify: (code: string) => Promise<GoAuthResult<{ ok: true }>>;
		recovery: (code: string) => Promise<GoAuthResult<{ ok: true }>>;
		disable: () => Promise<GoAuthResult<null>>;
		status: () => Promise<GoAuthResult<TotpStatus>>;
		regenerateRecoveryCodes: () => Promise<GoAuthResult<{ recoveryCodes: string[] }>>;
	};
}
