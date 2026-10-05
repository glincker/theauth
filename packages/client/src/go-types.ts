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
	signup: (input: { email: string; password: string }) => Promise<GoAuthResult<{ ok: true }>>;
	logout: () => Promise<GoAuthResult<null>>;
	forgotPassword: (email: string) => Promise<GoAuthResult<{ sent: boolean }>>;
	resetPassword: (input: {
		token: string;
		newPassword: string;
	}) => Promise<GoAuthResult<{ ok: true }>>;
	session: {
		get: () => Promise<GoAuthResult<GoUser>>;
		revokeCurrent: () => Promise<GoAuthResult<null>>;
	};
	passkeys: {
		isSupported: () => boolean;
		register: (name?: string) => Promise<GoAuthResult<PasskeyCredential>>;
		login: () => Promise<GoAuthResult<{ ok: true }>>;
		list: () => Promise<GoAuthResult<PasskeyCredential[]>>;
		remove: (id: string) => Promise<GoAuthResult<null>>;
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
	};
}
