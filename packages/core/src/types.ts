import type { AgentConfirmation } from "./agent/confirmation.js";
import type { AgentConfig } from "./agent/types.js";
import type { ApprovalConfig } from "./approval/approval.js";
import type { ChainCheckpointOptions, ChainCheckpointResult } from "./audit/chain-anchor.js";
import type { InputSource, InputSourceKind, ProvenanceFilter } from "./audit/provenance.js";
import type { PseudonymRotation } from "./audit/pseudonym-rotation.js";
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
import type { DeviceConfig } from "./device/types.js";
import type { DidWebConfig } from "./did/types.js";
import type { TheAuthHooks } from "./hooks/lifecycle.js";
import type { HookSafetyConfig } from "./hooks/safety.js";
import type { McpConfig, Result } from "./mcp/types.js";
import type { ObservabilityConfig, TheAuthLogger } from "./observability/types.js";
import type { DecisionCode } from "./permission/codes.js";
import type { PermissionCatalog } from "./permission/typed.js";
import type { TheAuthPlugin } from "./plugin/types.js";
import type { ResourceMatching } from "./policy/resource-match.js";
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
	/** IoT devices as principals (`theauth.device`). Needs `agents`. See docs/iot-devices.mdx. */
	devices?: DeviceConfig;

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
	/**
	 * Optional permission catalog (see `definePermissions`). Declaring it narrows `resource` and `action` on the returned instance at the type level. Not enforced at runtime.
	 */
	permissions?: PermissionCatalog;
	/**
	 * Timeout and failure policy for `hooks.beforeAuthorize` and `hooks.beforeAgentCreate`. Sibling of `hooks` so the hooks object stays a plain map of functions. Defaults: 2000 ms timeout, deny on timeout or error for beforeAuthorize, throw for beforeAgentCreate. Env: THEAUTH_HOOK_TIMEOUT_MS, THEAUTH_HOOK_ON_TIMEOUT, THEAUTH_HOOK_ON_ERROR.
	 */
	hookSafety?: HookSafetyConfig;
	/**
	 * Structured logger for library diagnostics (hook timeouts, listener failures, startup warnings). Default: no-op, the SDK never writes to the console on its own.
	 */
	logger?: TheAuthLogger;
	/**
	 * Decision events for metrics and tracing: `onDecision(event)` fires once per authorize, authorizeByToken and policy.evaluate decision, off the request path. See `docs/observability.mdx`.
	 */
	observability?: ObservabilityConfig;

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

	/**
	 * How a permission `resource` pattern is compared to the requested resource, for authorize(), the policy engine, delegation, simulate, explain, device bundles and the token vault. `colon` (default) honors `*` only as a whole `:` segment. `path` also lets `/` separate segments inside a colon segment: `*` matches one, `**` matches one or more, never an empty, `.` or `..` segment. Turning it on only changes patterns that have a `*` or `**` path segment, which were literal text before. `policy.resourceMatching` overrides this for the unified policy engine alone.
	 */
	resourceMatching?: ResourceMatching;

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
	/** Append a signed anchor for each chain's current first row; returns anchors and heads to pin outside the database. */
	checkpoint: (opts?: ChainCheckpointOptions) => Promise<Result<ChainCheckpointResult>>;
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
/** Every agent type, including the `device` type of IoT device backing agents. */
export type AgentType = "autonomous" | "delegated" | "service" | "device";

export interface AgentIdentity {
	id: string;
	ownerId: string;
	tenantId?: string;
	name: string;
	/** `device` marks the backing agent of an IoT device (see `theauth.device`). Never accepted on create. */
	type: AgentType;
	token: string;
	permissions: Permission[];
	status: "active" | "revoked" | "expired";
	expiresAt: Date | null;
	/** Sender constraint of the token (RFC 7800): `jkt` for DPoP, `x5t#S256` for mutual TLS. Absent for a plain bearer token. See `docs/dpop-agent-tokens.mdx`. */
	cnf?: AgentConfirmation;
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
	/** `device` is refused here: device agents are created by `theauth.device.register`. It is in the union so `beforeAgentCreate` policies see device registrations. */
	type: AgentType;
	permissions: Permission[];
	expiresAt?: Date;
	metadata?: Record<string, unknown>;
	/** Bind the token to a key or certificate (RFC 7800). The token then works only for a request that proves the key, for example with a DPoP proof (RFC 9449). */
	cnf?: AgentConfirmation;
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
	/** Device backing agents are left out unless `type: "device"` is asked for. */
	type?: AgentType;
}

export interface AuthorizeResult {
	allowed: boolean;
	reason?: string;
	auditId: string;
	/** Machine-readable outcome. Always set by core; optional on the type so hand-built results in user code still compile. */
	code?: DecisionCode;
}

export type AuthorizeFn = (agentId: string, request: AuthorizeRequest) => Promise<AuthorizeResult>;

export interface RequestContext {
	/** Proofs of possession the transport already verified for this request, by `cnf` member (`jkt`, `x5t#S256`). An agent token bound with `cnf` is refused unless these match. Set it only from verified data, `requireAgent` and the HTTP handler do. */
	confirmation?: AgentConfirmation;
	/** Client IP address, used for ipAllowlist enforcement and audit logging */
	ip?: string;
	userAgent?: string;
	/** Where the inputs of this call came from. Recorded in the audit row as kind, id and content hash, never the content. */
	inputs?: InputSource[];
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
	/**
	 * Rotate the id pseudonyms. Each period uses its own random secret, so one subject has a different pseudonym in every period, and once an old period secret is shredded nobody, the key holder included, can link a subject across periods. Off by default (one stable pseudonym per subject).
	 */
	pseudonymRotation?: PseudonymRotation;
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
	/** Machine-readable outcome. Undefined on rows written before `decision_code` existed. An index convenience, not part of the audit hash. */
	code?: DecisionCode;
	/** What happened (see AuditEvent). `action` is the domain verb. Null on rows from writers that do not set it. Not part of the audit hash. */
	event: AuditEvent | null;
	durationMs: number;
	tokensCost?: number;
	/** Inputs the caller said were in context for this call (kind, optional id, content hash). Never the content. Absent when none were recorded. */
	inputs?: AuditInputRef[];
	timestamp: Date;
}

/** One recorded input of a call. `hv` is 2 for the keyed hash, absent for plain SHA-256 hashes of older rows. */
export interface AuditInputRef {
	kind: InputSourceKind;
	id?: string;
	hash: string;
	hv?: 2;
}

/**
 * The audit event vocabulary. `event` says what happened, `action` keeps the domain verb
 * (`read`, `write`, or the tool name). The list is open: unknown writers may add their own.
 */
export type AuditEvent =
	| "authorize"
	| "authorize.token"
	| "policy.evaluate"
	| "mcp.tool.call"
	| "delegation.create"
	| "delegation.revoke"
	| "agent.create"
	| "agent.revoke"
	| "agent.cascade.revoked"
	| "approval.request"
	| "approval.approve"
	| "approval.deny"
	| "vault.read"
	| "audit.checkpoint"
	| "audit.write_failed"
	| "audit.erasure"
	| (string & {});

/** One page of audit entries. `nextCursor` is null on the last page. */
export interface AuditPage {
	entries: AuditEntry[];
	nextCursor: string | null;
}

export interface AuditFilter {
	agentId?: string;
	userId?: string;
	since?: Date;
	until?: Date;
	actions?: string[];
	result?: "allowed" | "denied" | "rate_limited" | "escalated";
	/** Only rows whose `decision_code` is one of these. */
	codes?: DecisionCode[];
	/** Only rows with one of these events. */
	events?: AuditEvent[];
	/** Exact resource, or a prefix when it ends with `*` (for example `mcp:github:*`). */
	resource?: string;
	/** Only rows that recorded an input of this kind and/or with this content hash (see `hashInputContent`). */
	provenance?: ProvenanceFilter;
	/** Write order. Default "desc" (newest first), unchanged from earlier versions. */
	order?: "asc" | "desc";
	/** Opaque cursor from `AuditPage.nextCursor`. Continue the same filter and order from where the last page ended. */
	cursor?: string;
	limit?: number;
	/** Deprecated: use `cursor`. Skips rows and drifts when rows are written between pages. */
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
