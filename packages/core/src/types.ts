import type { AgentConfig } from "./agent/types.js";
import type { ApprovalConfig } from "./approval/approval.js";
import type {
	AgentReplay,
	AuditChainExportOptions,
	AuditExport,
	ReplayOptions,
} from "./audit/replay.js";
import type { VerifyAuditChainOptions, VerifyAuditChainResult } from "./audit/verify.js";
import type { AdminConfig } from "./auth/admin.js";
import type { ApiKeyManagerConfig } from "./auth/api-key-manager.js";
import type { CaptchaConfig } from "./auth/captcha.js";
import type { TrustedProxyConfig } from "./auth/client-ip.js";
import type { EmailOtpConfig } from "./auth/email-otp.js";
import type { EmailVerificationConfig } from "./auth/email-verification.js";
import type { MagicLinkConfig } from "./auth/magic-link.js";
import type { OrgConfig } from "./auth/organization.js";
import type { PasskeyConfig } from "./auth/passkey.js";
import type { PasswordResetConfig } from "./auth/password-reset.js";
import type { PhoneAuthConfig } from "./auth/phone.js";
import type { SignInGateConfig } from "./auth/sign-in-gate.js";
import type { SsoConfig } from "./auth/sso.js";
import type { TotpConfig } from "./auth/totp.js";
import type { AuthAdapter } from "./auth/types.js";
import type { UsernameAuthConfig } from "./auth/username.js";
import type { WebhookConfig } from "./auth/webhooks.js";
import type { DatabaseConfig } from "./db/database.js";
import type { DidWebConfig } from "./did/types.js";
import type { TheAuthHooks } from "./hooks/lifecycle.js";
import type { McpConfig, Result } from "./mcp/types.js";
import type { TheAuthPlugin } from "./plugin/types.js";
import type { PolicyEngineConfig } from "./policy/types.js";
import type { RedirectConfig } from "./redirect/chain.js";
import type { SessionFreshnessConfig } from "./session/freshness.js";
import type { SessionConfig } from "./session/session.js";
import type { SecondaryStorageConfig } from "./storage/types.js";

export type { DatabaseConfig };

/** Main configuration for TheAuth. */
export interface TheAuthConfig {
	database: DatabaseConfig;

	agents?: AgentConfig;

	audit?: AuditConfig;

	mcp?: McpConfig;

	/** Human auth: plug in an existing auth provider via `adapter`, or enable built-in sessions with `session`. */
	auth?: {
		adapter?: AuthAdapter;
		session?: SessionConfig;
	};

	/** Async approval flows (CIBA-style human-in-the-loop) */
	approval?: ApprovalConfig;

	/** Lifecycle hooks for agent sandboxing, logging, and custom validation */
	hooks?: TheAuthHooks;

	did?: {
		/** did:web config, required for generating did:web identities. */
		web?: DidWebConfig;
	};

	/** Auth plugins (email, OAuth, 2FA, org, etc.) */
	plugins?: TheAuthPlugin[];

	/** Storage for short-lived state: rate limit counters, device codes, nonces, caches. */
	secondaryStorage?: SecondaryStorageConfig;

	/** How to find the real client IP behind proxies. Forwarded headers are not trusted unless you say how. */
	trustedProxy?: TrustedProxyConfig;

	/** Base URL for the auth server */
	baseUrl?: string;

	/** Hosts this deployment may answer on: custom domains, tenant subdomains, preview URLs. */
	allowedHosts?: string[];

	/** Honor `X-Forwarded-Host` and `X-Forwarded-Proto` when matching `allowedHosts`. Only enable behind a trusted proxy. */
	trustForwardedHeaders?: boolean;

	/** Secret key for signing tokens */
	secret?: string;

	/** Magic link (passwordless email) authentication. Enables `theauth.magicLink`. */
	magicLink?: MagicLinkConfig;

	/** Email OTP (one-time password) login. Enables `theauth.emailOtp`. */
	emailOtp?: EmailOtpConfig;

	/** Email verification flow. Enables `theauth.emailVerification`. */
	emailVerification?: EmailVerificationConfig;

	/** TOTP two-factor authentication. Enables `theauth.totp`. */
	totp?: TotpConfig;

	/** Central sign-in gate policy, applied to every session-issuing path. */
	signInGate?: SignInGateConfig;

	/** Passkey (WebAuthn) authentication. Enables `theauth.passkey`. */
	passkey?: PasskeyConfig;

	/** Organizations and RBAC. Enables `theauth.org`. */
	org?: OrgConfig;

	/** SAML 2.0 and OIDC enterprise SSO. Enables `theauth.sso`. */
	sso?: SsoConfig;

	/** Admin module. Enables `theauth.admin`. */
	admin?: AdminConfig;

	/** API key management. Enables `theauth.apiKeys`. */
	apiKeys?: ApiKeyManagerConfig;

	/** Username and password authentication. Enables `theauth.username`. */
	username?: UsernameAuthConfig;

	/** Password reset (forgot password) flow. Enables `theauth.passwordReset`. */
	passwordReset?: PasswordResetConfig;

	/** Phone (SMS OTP) authentication. Enables `theauth.phone`. */
	phone?: PhoneAuthConfig;

	/** Captcha (reCAPTCHA v2/v3, hCaptcha, Turnstile). Enables `theauth.captcha`. */
	captcha?: CaptchaConfig;

	/** Webhook endpoints to notify on auth events. Each entry has a URL and signing secret. */
	webhooks?: WebhookConfig[];

	/** Unified policy engine: LRU cache size and TTL, combine strategy, audit sampling. */
	policy?: PolicyEngineConfig;

	/** Redirect chain configuration. Enables `theauth.redirects`. */
	redirects?: RedirectConfig;

	/** Session freshness: maximum session age in seconds for sensitive operations. */
	sessionFreshness?: SessionFreshnessConfig;

	/** Emit IETF agentic JWT claims on issued tokens. */
	emitAgenticJwtClaims?: boolean;
}

/** @deprecated Use `TheAuthConfig` instead. Will be removed in a future major version. */
export type AuthConfig = TheAuthConfig;

/** The main TheAuth instance returned by createTheAuth(). */
export interface TheAuthInstance {
	agent: AgentModule;
	authorize: AuthorizeFn;
	delegate: DelegateFn;
	audit: AuditModule;
	mcp: McpModule;
}

/** @deprecated Use `TheAuthInstance` instead. Will be removed in a future major version. */
export type AuthInstance = TheAuthInstance;

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
	cleanup: (options: {
		retentionDays: number;
	}) => Promise<{ deleted: number; checkpoints?: number }>;
	/** Check the audit hash chain and report the first broken link. */
	verifyAuditChain: (opts: VerifyAuditChainOptions) => Promise<Result<VerifyAuditChainResult>>;
	/** Ordered timeline of one agent's activity with chain verification status. */
	replayAgent: (agentId: string, opts?: ReplayOptions) => Promise<Result<AgentReplay>>;
	/** JSONL export plus a signed manifest. */
	exportAudit: (opts?: AuditChainExportOptions) => Promise<Result<AuditExport>>;
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
	userAgent?: string;
}

export interface AuthorizeRequest {
	action: string;
	resource: string;
	arguments?: Record<string, unknown>;
	/** Id of an approved approval request. When the matched permission requires approval, authorize spends this request (single use) and allows the call. */
	approvalId?: string;
	ip?: string;
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
	/** Human owning the root agent of this chain, the accountable principal. */
	rootOwnerId?: string;
	path?: string[];
}

export type DelegateFn = (input: DelegateInput) => Promise<DelegationChain>;

export interface AuditConfig {
	/** Link each audit row to the previous one with a SHA-256 hash (one chain per agent). Off by default. */
	tamperEvident?: boolean;
	/** Secret for HMAC-SHA256 hashing. Set it so someone with write access to the database but not to this key cannot rewrite rows and recompute the chain. */
	hmacKey?: string;
	/** Called when a best-effort audit write fails. */
	onAuditError?: (info: { error: unknown; pendingFailures: number; totalFailures: number }) => void;
}

export interface AuditEntry {
	id: string;
	agentId: string;
	userId: string;
	action: string;
	resource: string;
	parameters: Record<string, unknown>;
	result: "allowed" | "denied" | "rate_limited" | "escalated";
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
	result?: "allowed" | "denied" | "rate_limited" | "escalated";
	limit?: number;
	offset?: number;
}

export interface AuditExportOptions {
	format: "json" | "csv";
	since?: Date;
	until?: Date;
	userId?: string;
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
