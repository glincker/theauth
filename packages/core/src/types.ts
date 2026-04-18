import type { AgentConfig } from "./agent/types.js";
import type { ApprovalConfig } from "./approval/approval.js";
import type { AdminConfig } from "./auth/admin.js";
import type { ApiKeyManagerConfig } from "./auth/api-key-manager.js";
import type { CaptchaConfig } from "./auth/captcha.js";
import type { EmailOtpConfig } from "./auth/email-otp.js";
import type { EmailVerificationConfig } from "./auth/email-verification.js";
import type { MagicLinkConfig } from "./auth/magic-link.js";
import type { OrgConfig } from "./auth/organization.js";
import type { PasskeyConfig } from "./auth/passkey.js";
import type { PasswordResetConfig } from "./auth/password-reset.js";
import type { PhoneAuthConfig } from "./auth/phone.js";
import type { SsoConfig } from "./auth/sso.js";
import type { TotpConfig } from "./auth/totp.js";
import type { AuthAdapter } from "./auth/types.js";
import type { UsernameAuthConfig } from "./auth/username.js";
import type { WebhookConfig } from "./auth/webhooks.js";
import type { DatabaseConfig } from "./db/database.js";
import type { DidWebConfig } from "./did/types.js";
import type { KavachHooks } from "./hooks/lifecycle.js";
import type { McpConfig } from "./mcp/types.js";
import type { KavachPlugin } from "./plugin/types.js";
import type { PolicyEngineConfig } from "./policy/types.js";
import type { RedirectConfig } from "./redirect/chain.js";
import type { SessionFreshnessConfig } from "./session/freshness.js";
import type { SessionConfig } from "./session/session.js";

export type { DatabaseConfig };

/**
 * Main configuration for KavachOS
 */
export interface KavachConfig {
	/** Database connection - Drizzle instance or connection config */
	database: DatabaseConfig;

	/** Agent identity configuration */
	agents?: AgentConfig;

	/** MCP authorization server configuration */
	mcp?: McpConfig;

	/**
	 * Human auth configuration.
	 *
	 * `adapter` plugs in an existing auth provider (better-auth, Auth.js,
	 * Clerk, custom) so KavachOS can resolve the human user behind an
	 * incoming request.
	 *
	 * `session` enables KavachOS-managed session tokens backed by the
	 * `kavach_sessions` database table.  When provided, the returned
	 * `kavach.auth.session` manager is available for creating, validating,
	 * and revoking sessions.
	 *
	 * When omitted entirely the instance operates in *manual user management*
	 * mode – `kavach.auth.resolveUser()` always returns `null`.
	 */
	auth?: {
		adapter?: AuthAdapter;
		session?: SessionConfig;
	};

	/** Async approval flows (CIBA-style human-in-the-loop) */
	approval?: ApprovalConfig;

	/** Lifecycle hooks for agent sandboxing, logging, and custom validation */
	hooks?: KavachHooks;

	/** W3C DID (Decentralized Identifiers) configuration */
	did?: {
		/** did:web config — required for generating did:web identities */
		web?: DidWebConfig;
	};

	/** Auth plugins (email, OAuth, 2FA, org, etc.) */
	plugins?: KavachPlugin[];

	/** Base URL for the auth server */
	baseUrl?: string;

	/** Secret key for signing tokens */
	secret?: string;

	/**
	 * Magic link (passwordless email) authentication.
	 *
	 * When provided, `kavach.magicLink` is available with `sendLink`,
	 * `verify`, and `handleRequest`. Requires `auth.session` to be configured
	 * so that sessions can be issued on successful verification.
	 */
	magicLink?: MagicLinkConfig;

	/**
	 * Email OTP (one-time password) authentication.
	 *
	 * When provided, `kavach.emailOtp` is available with `sendCode`,
	 * `verifyCode`, and `handleRequest`. Requires `auth.session` to be
	 * configured so that sessions can be issued on successful verification.
	 */
	emailOtp?: EmailOtpConfig;

	/**
	 * Email verification flow.
	 *
	 * When provided, `kavach.emailVerification` is available with
	 * `sendVerification`, `verify`, `isVerified`, and `handleRequest`.
	 * The caller provides a `sendVerificationEmail` callback to deliver the
	 * link.
	 */
	emailVerification?: EmailVerificationConfig;

	/**
	 * TOTP two-factor authentication.
	 *
	 * When provided, `kavach.totp` is available with `setup`, `enable`,
	 * `disable`, `verify`, `isEnabled`, `regenerateBackupCodes`, and
	 * `handleRequest`. Users call `setup` to get a secret + backup codes,
	 * then `enable` after scanning their authenticator app.
	 */
	totp?: TotpConfig;

	/**
	 * Passkey / WebAuthn authentication.
	 *
	 * When provided, `kavach.passkey` is available for registering and
	 * authenticating with platform authenticators (Face ID, Touch ID,
	 * Windows Hello) and roaming authenticators (hardware security keys).
	 */
	passkey?: PasskeyConfig;

	/**
	 * Organizations + RBAC.
	 *
	 * When provided, `kavach.org` is available with org CRUD, membership
	 * management, invitation flows, and role-based permission checking.
	 */
	org?: OrgConfig;

	/**
	 * SSO (SAML 2.0 + OIDC) enterprise authentication.
	 *
	 * When provided, `kavach.sso` is available for creating org-level SSO
	 * connections, generating auth URLs, and processing callbacks.
	 */
	sso?: SsoConfig;

	/**
	 * Admin module.
	 *
	 * When provided, `kavach.admin` is available for listing users, banning,
	 * impersonation, and deletion.
	 */
	admin?: AdminConfig;

	/**
	 * API key management.
	 *
	 * When provided, `kavach.apiKeys` is available for creating and validating
	 * static API keys with permission scopes.
	 */
	apiKeys?: ApiKeyManagerConfig;

	/**
	 * Username + password authentication.
	 *
	 * When provided, `kavach.username` is available with `signUp`, `signIn`,
	 * `changePassword`, `changeUsername`, and `handleRequest`. Requires
	 * `auth.session` to be configured so that sessions can be issued.
	 */
	username?: UsernameAuthConfig;

	/**
	 * Password reset (forgot password) flow.
	 *
	 * When provided, `kavach.passwordReset` is available with `requestReset`,
	 * `resetPassword`, and `handleRequest`. Requires `username` and
	 * `auth.session` to be configured. The caller provides a `sendResetEmail`
	 * callback to deliver the reset link.
	 */
	passwordReset?: PasswordResetConfig;

	/**
	 * Phone number (SMS OTP) authentication.
	 *
	 * When provided, `kavach.phone` is available with `sendCode`, `verifyCode`,
	 * and `handleRequest`. Requires `auth.session` to be configured.
	 */
	phone?: PhoneAuthConfig;

	/**
	 * Captcha integration (reCAPTCHA v2/v3, hCaptcha, Cloudflare Turnstile).
	 *
	 * When provided, `kavach.captcha` is available with `verify` and
	 * `middleware`.
	 */
	captcha?: CaptchaConfig;

	/**
	 * Webhook endpoints to notify on auth events.
	 *
	 * Each entry specifies a URL, signing secret, and the events it subscribes
	 * to. Deliveries are fire-and-forget with exponential backoff retries.
	 */
	webhooks?: WebhookConfig[];

	/**
	 * Unified policy engine configuration.
	 *
	 * Controls the LRU cache (max entries, TTL), combining strategy
	 * (deny-overrides vs permit-overrides), audit emission, and audit
	 * sample rate. When omitted, the engine runs with safe defaults:
	 * cache enabled (10,000 entries, 60s TTL), deny-overrides, full audit.
	 */
	policy?: PolicyEngineConfig;

	/**
	 * Redirect chain configuration.
	 *
	 * When provided, `kavach.redirects` is available for capturing the user's
	 * original destination before auth flows and restoring it afterwards,
	 * with support for intermediate steps (onboarding, email verification, etc.).
	 */
	redirects?: RedirectConfig;

	/**
	 * Session freshness configuration.
	 *
	 * Controls the maximum session age (in seconds) for sensitive operations.
	 * When omitted, defaults to 300 seconds (5 minutes).
	 */
	sessionFreshness?: SessionFreshnessConfig;

	/**
	 * Emit IETF agentic JWT claims on issued tokens.
	 *
	 * When true, tokens issued by the MCP token endpoint and the JWT session
	 * module include additional claims defined in draft-goswami-agentic-jwt-00
	 * and draft-liu-agent-operation-authorization-01, such as `agent_id`,
	 * `agent_type`, and `trust_tier`. Off by default to preserve backward
	 * compatibility with existing token consumers.
	 *
	 * @default false
	 */
	emitAgenticJwtClaims?: boolean;
}

/**
 * The main KavachOS instance returned by createKavach()
 */
export interface KavachInstance {
	/** Agent identity management */
	agent: AgentModule;
	/** Authorization engine */
	authorize: AuthorizeFn;
	/** Delegation chain management */
	delegate: DelegateFn;
	/** Audit log queries */
	audit: AuditModule;
	/** MCP authorization server */
	mcp: McpModule;
}

export interface AgentModule {
	create: (input: CreateAgentInput) => Promise<AgentIdentity>;
	get: (agentId: string) => Promise<AgentIdentity | null>;
	list: (filter?: AgentFilter) => Promise<AgentIdentity[]>;
	update: (agentId: string, input: UpdateAgentInput) => Promise<AgentIdentity>;
	revoke: (agentId: string) => Promise<void>;
	rotate: (agentId: string) => Promise<AgentIdentity>;
}

export interface AuditModule {
	query: (filter: AuditFilter) => Promise<AuditEntry[]>;
	export: (options: AuditExportOptions) => Promise<string>;
}

export interface McpModule {
	register: (input: McpServerInput) => Promise<McpServer>;
	validate: (token: string) => Promise<TokenValidationResult>;
	middleware: () => McpMiddleware;
}

// Placeholder types - will be fully defined in their respective modules
export interface AgentIdentity {
	id: string;
	ownerId: string;
	tenantId?: string;
	name: string;
	type: "autonomous" | "delegated" | "service";
	token: string;
	permissions: Permission[];
	status: "active" | "revoked" | "expired";
	expiresAt: Date | null;
	createdAt: Date;
	updatedAt: Date;
}

export interface Permission {
	resource: string;
	actions: string[];
	constraints?: PermissionConstraints;
	/** Optional ReBAC relation. When set, the policy engine queries the relationship graph. */
	relation?: string;
}

export interface PermissionConstraints {
	maxCallsPerHour?: number;
	allowedArgPatterns?: string[];
	requireApproval?: boolean;
	timeWindow?: { start: string; end: string };
	ipAllowlist?: string[];
}

export interface CreateAgentInput {
	ownerId: string;
	tenantId?: string;
	name: string;
	type: "autonomous" | "delegated" | "service";
	permissions: Permission[];
	expiresAt?: Date;
	metadata?: Record<string, unknown>;
}

export interface UpdateAgentInput {
	name?: string;
	permissions?: Permission[];
	expiresAt?: Date;
	metadata?: Record<string, unknown>;
}

export interface AgentFilter {
	userId?: string;
	tenantId?: string;
	status?: "active" | "revoked" | "expired";
	type?: "autonomous" | "delegated" | "service";
}

export interface AuthorizeResult {
	allowed: boolean;
	reason?: string;
	auditId: string;
}

export type AuthorizeFn = (agentId: string, request: AuthorizeRequest) => Promise<AuthorizeResult>;

export interface RequestContext {
	/** Client IP address, used for ipAllowlist enforcement and audit logging */
	ip?: string;
	/** User-Agent string from the originating HTTP request */
	userAgent?: string;
}

export interface AuthorizeRequest {
	action: string;
	resource: string;
	arguments?: Record<string, unknown>;
	/** Client IP address for ipAllowlist constraint enforcement */
	ip?: string;
	/** HTTP request context (IP, User-Agent) for audit log enrichment */
	context?: RequestContext;
}

export interface DelegateInput {
	fromAgent: string;
	toAgent: string;
	permissions: Permission[];
	expiresAt: Date;
	maxDepth?: number;
}

export interface DelegationChain {
	id: string;
	fromAgent: string;
	toAgent: string;
	permissions: Permission[];
	expiresAt: Date;
	depth: number;
	createdAt: Date;
}

export type DelegateFn = (input: DelegateInput) => Promise<DelegationChain>;

export interface AuditEntry {
	id: string;
	agentId: string;
	userId: string;
	action: string;
	resource: string;
	parameters: Record<string, unknown>;
	result: "allowed" | "denied" | "rate_limited";
	reason?: string;
	durationMs: number;
	tokensCost?: number;
	timestamp: Date;
}

export interface AuditFilter {
	agentId?: string;
	userId?: string;
	since?: Date;
	until?: Date;
	actions?: string[];
	result?: "allowed" | "denied" | "rate_limited";
	limit?: number;
	offset?: number;
}

export interface AuditExportOptions {
	format: "json" | "csv";
	since?: Date;
	until?: Date;
}

export interface McpServerInput {
	name: string;
	endpoint: string;
	tools: string[];
	authRequired?: boolean;
	rateLimit?: { rpm: number };
}

export interface McpServer {
	id: string;
	name: string;
	endpoint: string;
	tools: string[];
	authRequired: boolean;
	createdAt: Date;
}

export interface TokenValidationResult {
	valid: boolean;
	agentId?: string;
	userId?: string;
	scopes?: string[];
	expiresAt?: Date;
}

export type McpMiddleware = (request: Request) => Promise<Response | undefined>;
