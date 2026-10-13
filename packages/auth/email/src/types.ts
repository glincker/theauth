/** Outcome of a gate evaluation (mirrors core `SignInGateDecision`). */
export type EmailGateDecision =
	| { action: "allow" }
	| { action: "password_change_required"; challenge: string; expiresAt: Date }
	| { action: "two_factor_required"; challenge: string; methods: string[]; expiresAt: Date };

/**
 * Structural view of the core sign-in gate (`ctx.signInGate`). Kept local so
 * this package does not need a newer core at type level.
 */
export interface EmailSignInGate {
	evaluate(input: {
		userId: string;
		method: "password";
		request?: Request;
	}): Promise<EmailGateDecision>;
	registerPasswordChanger(
		changer: (
			userId: string,
			newPassword: string,
		) => Promise<"changed" | "no_account" | { error: string }>,
	): void;
	registerPasswordCredentialCheck(check: (userId: string) => Promise<boolean>): void;
	onPasswordChanged(userId: string): Promise<void>;
}

export interface EmailSessionLimit {
	/** Maximum concurrent sessions per user (unset: no limit). */
	maxConcurrent?: number;
	/** `evict-oldest` (default) or `reject`. */
	onLimit?: "evict-oldest" | "reject";
}

export interface EmailAuthConfig {
	/**
	 * Sign-in gate (forced password change, 2FA policy). The plugin fills this
	 * from `ctx.signInGate`; pass it explicitly when using `createEmailAuth`.
	 */
	signInGate?: EmailSignInGate;
	/** Concurrent session limit applied to sessions this module creates. */
	sessionLimit?: EmailSessionLimit;
	/** Send verification email. You provide the transport. */
	sendVerificationEmail: (email: string, token: string, url: string) => Promise<void>;
	/** Send password reset email. */
	sendResetEmail: (email: string, token: string, url: string) => Promise<void>;
	/** Base URL for verification/reset links (e.g., "https://app.example.com") */
	appUrl: string;
	/** Password requirements */
	password?: {
		minLength?: number; // default: 8
		maxLength?: number; // default: 128
		requireUppercase?: boolean; // default: false
		requireNumber?: boolean; // default: false
		requireSpecial?: boolean; // default: false
	};
	/** Verification token expiry in seconds (default: 86400 = 24h) */
	verificationExpiry?: number;
	/** Reset token expiry in seconds (default: 3600 = 1h) */
	resetExpiry?: number;
	/** Whether email verification is required before login (default: true) */
	requireVerification?: boolean;
}

export interface PasswordConfig {
	minLength: number;
	maxLength: number;
	requireUppercase: boolean;
	requireNumber: boolean;
	requireSpecial: boolean;
}

export interface EmailUser {
	id: string;
	email: string;
	name: string | null;
	emailVerified: boolean;
	createdAt: Date;
	updatedAt: Date;
}

export interface SignUpInput {
	email: string;
	password: string;
	name?: string;
}

export interface SignInInput {
	email: string;
	password: string;
}

export interface EmailAuthModule {
	/** Register a new user */
	signUp: (input: SignUpInput) => Promise<{ user: EmailUser; token: string }>;
	/** Sign in with email and password */
	signIn: (
		input: SignInInput,
		context?: { request?: Request },
	) => Promise<{ user: EmailUser; session: { token: string; expiresAt: Date } }>;
	/** Verify email with token */
	verifyEmail: (token: string) => Promise<{ verified: boolean }>;
	/** Request password reset */
	requestReset: (email: string) => Promise<void>;
	/** Reset password with token */
	resetPassword: (token: string, newPassword: string) => Promise<{ success: boolean }>;
	/** Change password (authenticated) */
	changePassword: (
		userId: string,
		currentPassword: string,
		newPassword: string,
	) => Promise<{ success: boolean }>;
	/** Get user by ID */
	getUser: (userId: string) => Promise<EmailUser | null>;
	/** Get user by email */
	getUserByEmail: (email: string) => Promise<EmailUser | null>;
	/** Handle HTTP request (route to appropriate handler) */
	handleRequest: (request: Request) => Promise<Response | null>;
}

/** Internal row type for theauth_email_accounts */
export interface EmailAccountRow {
	id: string;
	userId: string;
	passwordHash: string;
	emailVerified: number; // 0 | 1 (SQLite boolean)
	verificationToken: string | null;
	verificationExpires: number | null; // unix timestamp ms
	resetToken: string | null;
	resetExpires: number | null; // unix timestamp ms
	createdAt: number; // unix timestamp ms
	updatedAt: number; // unix timestamp ms
}
