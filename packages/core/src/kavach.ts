import { eq } from "drizzle-orm";
import { createAgentModule } from "./agent/agent.js";
import { createPrivilegeAnalyzer } from "./analyzer/privilege.js";
import { createApprovalModule } from "./approval/approval.js";
import { createAuditModule } from "./audit/audit.js";
import type { AdminModule } from "./auth/admin.js";
import { createAdminModule } from "./auth/admin.js";
import type { ApiKeyManagerModule } from "./auth/api-key-manager.js";
import { createApiKeyManagerModule } from "./auth/api-key-manager.js";
import type { CaptchaModule } from "./auth/captcha.js";
import { createCaptchaModule } from "./auth/captcha.js";
import type { EmailOtpModule } from "./auth/email-otp.js";
import { createEmailOtpModule } from "./auth/email-otp.js";
import type { EmailVerificationModule } from "./auth/email-verification.js";
import { createEmailVerificationModule } from "./auth/email-verification.js";
import type { MagicLinkModule } from "./auth/magic-link.js";
import { createMagicLinkModule } from "./auth/magic-link.js";
import { createOneTimeTokenModule } from "./auth/one-time-token.js";
import type { OrgModule } from "./auth/organization.js";
import { createOrgModule } from "./auth/organization.js";
import type { PasskeyModule } from "./auth/passkey.js";
import { createPasskeyModule } from "./auth/passkey.js";
import type { PasswordResetModule } from "./auth/password-reset.js";
import { createPasswordResetModule } from "./auth/password-reset.js";
import type { PhoneAuthModule } from "./auth/phone.js";
import { createPhoneAuthModule } from "./auth/phone.js";
import type { SsoModule } from "./auth/sso.js";
import { createSsoModule } from "./auth/sso.js";
import type { TotpModule } from "./auth/totp.js";
import { createTotpModule } from "./auth/totp.js";
import type { ResolvedUser } from "./auth/types.js";
import type { UsernameAuthModule } from "./auth/username.js";
import { createUsernameAuthModule } from "./auth/username.js";
import type { WebhookModule } from "./auth/webhooks.js";
import { createWebhookModule } from "./auth/webhooks.js";
import { generateId } from "./crypto/web-crypto.js";
import { createDatabase } from "./db/database.js";
import { createTables } from "./db/migrations.js";
import { mcpServers, users } from "./db/schema.js";
import { createDelegationModule } from "./delegation/delegation.js";
import { createDidModule } from "./did/module.js";
import type { ViolationType } from "./hooks/lifecycle.js";
import { createPermissionEngine } from "./permission/engine.js";
import { buildClearCookie, extractToken, json } from "./plugin/helpers.js";
import { createPluginRouter } from "./plugin/router.js";
import { initializePlugins } from "./plugin/runner.js";
import type { EndpointContext } from "./plugin/types.js";
import { createPolicyModule } from "./policies/budget.js";
import { createPolicyEngine } from "./policy/engine.js";
import type { PolicyEngine } from "./policy/types.js";
import type { RedirectChainManager } from "./redirect/chain.js";
import { createRedirectChain } from "./redirect/chain.js";
import type { SessionFreshnessModule } from "./session/freshness.js";
import { createSessionFreshnessModule } from "./session/freshness.js";
import type { SessionManager } from "./session/session.js";
import { createSessionManager } from "./session/session.js";
import { createTenantModule } from "./tenant/tenant.js";
import { createTrustModule } from "./trust/scoring.js";
import type {
	AuditExportOptions,
	AuditFilter,
	AuthConfig,
	AuthorizeRequest,
	AuthorizeResult,
	DelegateInput,
	DelegationChain,
	McpServer,
	McpServerInput,
	RequestContext,
} from "./types.js";

/**
 * Map an authorization denial reason string to a violation type.
 * Falls back to 'permission_denied' when no more specific match is found.
 */
function classifyViolation(reason: string | undefined): ViolationType {
	const r = reason?.toLowerCase() ?? "";
	if (r.includes("rate") || r.includes("rate_limited")) return "rate_limited";
	if (r.includes("ip") || r.includes("allowlist")) return "ip_blocked";
	if (r.includes("time") || r.includes("window")) return "time_restricted";
	if (r.includes("approval")) return "approval_required";
	return "permission_denied";
}

/**
 * Create a TheAuth instance.
 *
 * The factory is **async** so it can open database connections for Postgres
 * and MySQL (which require async driver initialisation) and optionally run
 * `CREATE TABLE IF NOT EXISTS` for all schema tables.
 *
 * @example SQLite (simplest)
 * ```typescript
 * import { createTheAuth } from '@glinr/theauth';
 *
 * const auth = await createTheAuth({
 *   database: { provider: 'sqlite', url: 'theauth.db' },
 * });
 * ```
 *
 * @example Postgres
 * ```typescript
 * const auth = await createTheAuth({
 *   database: { provider: 'postgres', url: process.env.DATABASE_URL },
 * });
 * ```
 *
 * @example MySQL - skip auto-migration (tables managed externally)
 * ```typescript
 * const auth = await createTheAuth({
 *   database: {
 *     provider: 'mysql',
 *     url: process.env.DATABASE_URL,
 *     skipMigrations: true,
 *   },
 * });
 * ```
 */
export async function createTheAuth(config: TheAuthConfig) {
	const authAdapter = config.auth?.adapter ?? null;

	const db = await createDatabase(config.database);

	// Automatically create tables unless the caller has opted out.
	// Uses CREATE TABLE IF NOT EXISTS so it is safe to run every startup.
	if (!config.database.skipMigrations) {
		await createTables(db, config.database.provider, config);
	}

	// Unified policy engine. Always instantiated so kavach.policy is
	// available. Callers can tune it via config.policy (cache size, TTL,
	// combine strategy, audit sampling). Zero-config uses safe defaults.
	const policyEngine: PolicyEngine = createPolicyEngine({ db, config: config.policy });

	const agentConfig = {
		db,
		maxPerUser: config.agents?.maxPerUser ?? 10,
		defaultPermissions: config.agents?.defaultPermissions ?? [],
		tokenExpiry: config.agents?.tokenExpiry ?? "24h",
	};

	const agentModule = createAgentModule(agentConfig);

	const permissionEngine = createPermissionEngine({
		db,
		auditAll: config.agents?.auditAll ?? true,
	});

	const auditModule = createAuditModule({ db });

	const delegationModule = createDelegationModule({ db });

	// Session manager – only created when the caller opts in via auth.session.
	const sessionManager: SessionManager | null = config.auth?.session
		? createSessionManager(config.auth.session, db)
		: null;

	// Privilege analyzer — always available via kavach.analyzer.
	const privilegeAnalyzer = createPrivilegeAnalyzer(db);

	// Lifecycle hooks from config.
	const hooks = config.hooks ?? {};

	const tenantModule = createTenantModule(db);

	const policyModule = createPolicyModule(db);

	// Approval module — CIBA-style async human approval flows
	const approvalModule = createApprovalModule(config.approval ?? {}, db);

	// Trust module — graduated autonomy scoring
	const trustModule = createTrustModule({}, db);

	// DID module — W3C Decentralized Identifiers for agents
	const didModule = createDidModule(db, config.did);

	// Magic link — only created when the caller provides config.magicLink.
	// Requires a session manager to issue sessions on verification.
	const magicLinkModule: MagicLinkModule | null =
		config.magicLink && sessionManager
			? createMagicLinkModule(config.magicLink, db, sessionManager)
			: null;

	// Email OTP — only created when the caller provides config.emailOtp.
	// Requires a session manager to issue sessions on verification.
	const emailOtpModule: EmailOtpModule | null =
		config.emailOtp && sessionManager
			? createEmailOtpModule(config.emailOtp, db, sessionManager)
			: null;

	// TOTP — only created when the caller provides config.totp.
	const totpModule: TotpModule | null = config.totp ? createTotpModule(config.totp, db) : null;

	// Passkey — only created when the caller provides config.passkey.
	const passkeyModule: PasskeyModule | null = config.passkey
		? createPasskeyModule(config.passkey, db)
		: null;

	// Org — only created when the caller provides config.org.
	const orgModule: OrgModule | null = config.org ? createOrgModule(config.org, db) : null;

	// SSO — only created when the caller provides config.sso.
	const ssoModule: SsoModule | null = config.sso ? createSsoModule(config.sso, db) : null;

	// Admin — only created when the caller provides config.admin.
	const adminModule: AdminModule | null = config.admin
		? createAdminModule(config.admin, db, sessionManager)
		: null;

	// API Keys — only created when the caller provides config.apiKeys.
	const apiKeyManagerModule: ApiKeyManagerModule | null = config.apiKeys
		? createApiKeyManagerModule(config.apiKeys, db)
		: null;

	// Username auth — only created when the caller provides config.username.
	const usernameModule: UsernameAuthModule | null =
		config.username && sessionManager
			? createUsernameAuthModule(config.username, db, sessionManager)
			: null;

	// Password reset — only created when caller provides config.passwordReset + username + session.
	const oneTimeTokenModule = createOneTimeTokenModule({}, db);
	const passwordResetModule: PasswordResetModule | null =
		config.passwordReset && sessionManager
			? createPasswordResetModule(config.passwordReset, db, sessionManager, oneTimeTokenModule)
			: null;

	// Email verification — only created when caller provides config.emailVerification.
	const emailVerificationModule: EmailVerificationModule | null = config.emailVerification
		? createEmailVerificationModule(config.emailVerification, db, oneTimeTokenModule)
		: null;

	// Phone auth — only created when the caller provides config.phone.
	const phoneModule: PhoneAuthModule | null =
		config.phone && sessionManager ? createPhoneAuthModule(config.phone, db, sessionManager) : null;

	// Captcha — only created when the caller provides config.captcha.
	const captchaModule: CaptchaModule | null = config.captcha
		? createCaptchaModule(config.captcha)
		: null;

	// Redirect chain — always available (zero-config default).
	const redirectChain: RedirectChainManager = createRedirectChain(config.redirects);

	// Webhooks — only created when the caller provides config.webhooks.
	const webhookModule: WebhookModule | null =
		config.webhooks && config.webhooks.length > 0 ? createWebhookModule(config.webhooks) : null;

	// Plugin system — runs after core modules so plugins can depend on them.
	// Plugins may register endpoints, run migrations, and collect lifecycle hooks.
	const pluginRegistry = await initializePlugins(config.plugins ?? [], db, config, sessionManager);

	// Build an EndpointContext that plugins can use inside their handlers.
	// We capture sessionManager in closure so it's available if configured.
	const endpointCtx: EndpointContext = {
		db,
		async getUser(request: Request): Promise<ResolvedUser | null> {
			// 1. Try configured auth adapter first
			if (authAdapter) {
				const user = await authAdapter.resolveUser(request);
				if (user) return user;
			}

			// 2. Fall back to session-based resolution
			if (sessionManager) {
				const token = extractToken(request);
				if (!token) return null;

				try {
					const session = await sessionManager.validate(token);
					if (!session) return null;

					const userRows = await db.select().from(users).where(eq(users.id, session.userId));
					const user = userRows[0];
					if (!user) return null;

					return {
						id: user.id,
						email: user.email ?? undefined,
						name: user.name ?? undefined,
					};
				} catch {
					return null;
				}
			}

			return null;
		},
		async getSession(token: string) {
			if (!sessionManager) return null;
			return sessionManager.validate(token);
		},
	};

	const pluginRouter = createPluginRouter(pluginRegistry.endpoints);

	// Register core session endpoints when session manager is available
	if (sessionManager) {
		pluginRegistry.endpoints.push({
			method: "POST",
			path: "/auth/sign-out",
			metadata: { description: "Revoke the current session and clear cookie" },
			async handler(request) {
				const token = extractToken(request);
				if (!token) return json({ error: "No session" }, 401);

				try {
					const session = await sessionManager.validate(token);
					if (session) {
						await sessionManager.revoke(session.id);
					}
				} catch {
					// Token invalid — still clear the cookie
				}

				return new Response(JSON.stringify({ success: true }), {
					status: 200,
					headers: {
						"Content-Type": "application/json",
						"Set-Cookie": buildClearCookie("kavach_session"),
					},
				});
			},
		});

		pluginRegistry.endpoints.push({
			method: "GET",
			path: "/auth/session",
			metadata: { description: "Get current session and user info" },
			async handler(request) {
				const user = await endpointCtx.getUser(request);
				if (!user) return json({ error: "Not authenticated" }, 401);

				const token = extractToken(request);
				const session = token ? await sessionManager.validate(token) : null;

				return json({
					user,
					session: session ? { id: session.id, expiresAt: session.expiresAt } : null,
				});
			},
		});
	}

	// Authorize: look up agent, check own permissions then delegated permissions
	async function authorize(
		agentId: string,
		request: AuthorizeRequest,
		context?: RequestContext,
	): Promise<AuthorizeResult> {
		// beforeAuthorize hook — may block the request before any DB work
		if (hooks.beforeAuthorize) {
			const verdict = await hooks.beforeAuthorize({
				agentId,
				action: request.action,
				resource: request.resource,
				arguments: request.arguments,
			});
			if (verdict && !verdict.allow) {
				const reason = verdict.reason ?? "Blocked by beforeAuthorize hook";
				void hooks.onViolation?.({
					type: classifyViolation(reason),
					agentId,
					action: request.action,
					resource: request.resource,
					reason,
				});
				return { allowed: false, reason, auditId: "" };
			}
		}

		const agent = await agentModule.get(agentId);
		if (!agent) {
			return {
				allowed: false,
				reason: `Agent "${agentId}" not found`,
				auditId: "",
			};
		}
		if (agent.status !== "active") {
			return {
				allowed: false,
				reason: `Agent "${agent.name}" is ${agent.status}`,
				auditId: "",
			};
		}

		const enrichedRequest: AuthorizeRequest = context ? { ...request, context } : request;

		// First check the agent's own permissions
		const ownResult = await permissionEngine.authorize(agent, enrichedRequest);

		let finalResult: AuthorizeResult;

		if (ownResult.allowed) {
			finalResult = ownResult;
		} else {
			// If own permissions deny, check effective permissions from delegation chains
			const delegatedPerms = await delegationModule.getEffectivePermissions(agentId);

			if (delegatedPerms.length === 0) {
				finalResult = ownResult;
			} else {
				// Build a synthetic agent view with delegated permissions merged in
				const agentWithDelegated = { ...agent, permissions: delegatedPerms };
				const delegatedResult = await permissionEngine.authorize(
					agentWithDelegated,
					enrichedRequest,
				);
				// Both denied — return the original denial so the message references the agent by name
				finalResult = delegatedResult.allowed ? delegatedResult : ownResult;
			}
		}

		// afterAuthorize hook
		void hooks.afterAuthorize?.({
			agentId,
			action: request.action,
			resource: request.resource,
			result: {
				allowed: finalResult.allowed,
				reason: finalResult.reason,
				auditId: finalResult.auditId,
			},
		});

		// onViolation hook when the request was denied
		if (!finalResult.allowed) {
			void hooks.onViolation?.({
				type: classifyViolation(finalResult.reason),
				agentId,
				action: request.action,
				resource: request.resource,
				reason: finalResult.reason ?? "Authorization denied",
			});
		}

		return finalResult;
	}

	// Authorize by token: validate token then check permissions
	async function authorizeByToken(
		token: string,
		request: AuthorizeRequest,
		context?: RequestContext,
	): Promise<AuthorizeResult> {
		const agent = await agentModule.validateToken(token);
		if (!agent) {
			return {
				allowed: false,
				reason: "Invalid or expired agent token",
				auditId: "",
			};
		}
		const enrichedRequest: AuthorizeRequest = context ? { ...request, context } : request;
		return permissionEngine.authorize(agent, enrichedRequest);
	}

	// Delegate: verify parent permissions then create chain
	async function delegate(input: DelegateInput): Promise<DelegationChain> {
		const parentAgent = await agentModule.get(input.fromAgent);
		if (!parentAgent) throw new Error(`Parent agent "${input.fromAgent}" not found`);
		if (parentAgent.status !== "active") {
			throw new Error(`Parent agent "${parentAgent.name}" is ${parentAgent.status}`);
		}
		return delegationModule.delegate(input, parentAgent.permissions);
	}

	// Agent facade with hooks wired in
	const agentProxy = {
		async create(
			...args: Parameters<typeof agentModule.create>
		): ReturnType<typeof agentModule.create> {
			const [input] = args;

			if (hooks.beforeAgentCreate) {
				const verdict = await hooks.beforeAgentCreate(input);
				if (verdict && !verdict.allow) {
					throw new Error(verdict.reason ?? "Agent creation blocked by beforeAgentCreate hook");
				}
			}

			const agent = await agentModule.create(input);

			void hooks.afterAgentCreate?.(agent);

			return agent;
		},

		async revoke(agentId: string): ReturnType<typeof agentModule.revoke> {
			await agentModule.revoke(agentId);
			void hooks.onAgentRevoke?.(agentId);
		},

		async rotate(
			...args: Parameters<typeof agentModule.rotate>
		): ReturnType<typeof agentModule.rotate> {
			return agentModule.rotate(...args);
		},

		get: agentModule.get,
		list: agentModule.list,
		update: agentModule.update,
		validateToken: agentModule.validateToken,
	};

	// ── MCP server registry ─────────────────────────────────────────
	// Uses the kavach_mcp_servers table (defined in db/schema.ts).
	const mcpRegistry = {
		/**
		 * Register a new MCP tool server.
		 *
		 * Persists the server entry to the `kavach_mcp_servers` table.
		 * The returned record includes the generated `id` and `createdAt`.
		 */
		async register(input: McpServerInput): Promise<McpServer> {
			const now = new Date();
			const id = generateId();

			await db.insert(mcpServers).values({
				id,
				name: input.name,
				endpoint: input.endpoint,
				tools: input.tools,
				authRequired: input.authRequired ?? true,
				rateLimitRpm: input.rateLimit?.rpm ?? null,
				status: "active",
				createdAt: now,
				updatedAt: now,
			});

			return {
				id,
				name: input.name,
				endpoint: input.endpoint,
				tools: input.tools,
				authRequired: input.authRequired ?? true,
				createdAt: now,
			};
		},

		/**
		 * List all registered MCP servers (active and inactive).
		 */
		async list(): Promise<McpServer[]> {
			const rows = await db.select().from(mcpServers);
			return rows.map((row) => ({
				id: row.id,
				name: row.name,
				endpoint: row.endpoint,
				tools: row.tools,
				authRequired: row.authRequired,
				createdAt: row.createdAt,
			}));
		},

		/**
		 * Get a single MCP server by ID. Returns null when not found.
		 */
		async get(id: string): Promise<McpServer | null> {
			const rows = await db.select().from(mcpServers).where(eq(mcpServers.id, id));
			const row = rows[0];
			if (!row) return null;
			return {
				id: row.id,
				name: row.name,
				endpoint: row.endpoint,
				tools: row.tools,
				authRequired: row.authRequired,
				createdAt: row.createdAt,
			};
		},
	};

	return {
		agent: agentProxy,
		authorize,
		authorizeByToken,
		delegate,
		delegation: {
			revoke: delegationModule.revokeDelegation,
			getEffectivePermissions: delegationModule.getEffectivePermissions,
			listChains: delegationModule.listChains,
		},
		audit: {
			query: (filter: AuditFilter) => auditModule.query(filter),
			export: (options: AuditExportOptions) => auditModule.export(options),
			cleanup: (options: { retentionDays: number }) => auditModule.cleanup(options),
		},
		/**
		 * MCP server registration.
		 *
		 * Register and look up MCP tool servers. Uses the `kavach_mcp_servers`
		 * database table — no separate in-memory store needed.
		 */
		mcp: mcpRegistry,
		/**
		 * Least-privilege analyzer.
		 *
		 * Compare agent permissions against actual audit log usage to surface
		 * wildcards, unused grants, and over-permissioned identities.
		 */
		analyzer: {
			analyzeAgent: privilegeAnalyzer.analyzeAgent,
			analyzeAll: privilegeAnalyzer.analyzeAll,
			getSummary: privilegeAnalyzer.getSummary,
		},
		/**
		 * Human auth integration.
		 *
		 * `resolveUser` extracts the authenticated human from an inbound HTTP
		 * request via the configured adapter.  `session` is a full session
		 * manager (create / validate / revoke) when `auth.session` was passed
		 * to `createTheAuth()`.
		 *
		 * @example
		 * ```typescript
		 * app.use(async (req, res, next) => {
		 *   const user = await kavach.auth.resolveUser(req);
		 *   if (!user) return res.status(401).json({ error: 'Unauthorized' });
		 *   req.user = user;
		 *   next();
		 * });
		 * ```
		 */
		auth: {
			async resolveUser(request: Request): Promise<ResolvedUser | null> {
				if (!authAdapter) return null;
				return authAdapter.resolveUser(request);
			},
			session: sessionManager,
		},
		/**
		 * Resolve a human user from an incoming HTTP request.
		 *
		 * @deprecated Use `kavach.auth.resolveUser(request)` instead.
		 */
		async resolveUser(request: Request): Promise<ResolvedUser | null> {
			if (!authAdapter) return null;
			return authAdapter.resolveUser(request);
		},
		/** Direct database access for advanced usage */
		db,
		/**
		 * Multi-tenant isolation.
		 *
		 * Create and manage tenants (organizations) that share a single
		 * TheAuth instance with full data isolation. Agents can be scoped
		 * to a tenant via `tenantId`.
		 */
		tenant: tenantModule,
		/**
		 * Agent execution budget policies.
		 *
		 * Set spending caps (token cost, call counts) per agent, user, or
		 * tenant. Exceeded policies trigger a configurable action: warn,
		 * throttle, block, or revoke.
		 */
		policies: policyModule,
		/**
		 * CIBA-style async human approval flows.
		 *
		 * Create pending approval requests, notify humans via webhook or
		 * custom handler, and resolve them with approve / deny.
		 */
		approval: approvalModule,
		/**
		 * Graduated autonomy trust scoring.
		 *
		 * Compute and persist 0-100 trust scores derived from audit history,
		 * mapped to five levels: untrusted, limited, standard, trusted, elevated.
		 */
		trust: trustModule,
		/**
		 * W3C Decentralized Identifiers (DID) for agents.
		 *
		 * Generate did:key or did:web identities, sign payloads, and verify
		 * signatures. Private keys are never stored — they are returned to
		 * the caller on generation and must be stored securely.
		 *
		 * @example
		 * ```typescript
		 * const { agentDid, privateKeyJwk } = await kavach.did.generateKey(agentId);
		 * const signed = await kavach.did.sign(agentId, { action: 'read' }, privateKeyJwk);
		 * const result = await kavach.did.verify(signed.jws, agentDid.did);
		 * ```
		 */
		did: didModule,
		/**
		 * Magic link (passwordless email) authentication.
		 *
		 * Null when `magicLink` config was not provided or `auth.session` is not
		 * configured (sessions are required to issue tokens on verification).
		 *
		 * @example
		 * ```typescript
		 * // In your route handler
		 * const response = await kavach.magicLink?.handleRequest(request);
		 * if (response) return response;
		 * ```
		 */
		magicLink: magicLinkModule,
		/**
		 * Email OTP (one-time password) authentication.
		 *
		 * Null when `emailOtp` config was not provided or `auth.session` is not
		 * configured.
		 *
		 * @example
		 * ```typescript
		 * const response = await kavach.emailOtp?.handleRequest(request);
		 * if (response) return response;
		 * ```
		 */
		emailOtp: emailOtpModule,
		/**
		 * TOTP two-factor authentication.
		 *
		 * Null when `totp` config was not provided.
		 *
		 * @example
		 * ```typescript
		 * // On setup (show QR code to user)
		 * const { secret, uri, backupCodes } = await kavach.totp.setup(userId);
		 *
		 * // After user scans QR and enters code
		 * const { enabled } = await kavach.totp.enable(userId, totpCode);
		 *
		 * // On login (after password check)
		 * const { valid } = await kavach.totp.verify(userId, totpCode);
		 * ```
		 */
		totp: totpModule,
		/**
		 * Passkey / WebAuthn authentication.
		 *
		 * Null when `passkey` config was not provided.
		 *
		 * @example
		 * ```typescript
		 * // Registration — step 1: get options, send to browser
		 * const options = await kavach.passkey.getRegistrationOptions(userId, userName);
		 *
		 * // Registration — step 2: verify browser response
		 * const { credential } = await kavach.passkey.verifyRegistration(userId, response);
		 *
		 * // Authentication — step 1: get options
		 * const options = await kavach.passkey.getAuthenticationOptions(userId);
		 *
		 * // Authentication — step 2: verify browser response
		 * const result = await kavach.passkey.verifyAuthentication(response);
		 * if (result) console.log('Authenticated user:', result.userId);
		 * ```
		 */
		passkey: passkeyModule,
		/**
		 * Organizations + RBAC.
		 *
		 * Null when `org` config was not provided.
		 *
		 * @example
		 * ```typescript
		 * const org = await kavach.org?.create({ name: 'Acme', slug: 'acme', ownerId: userId });
		 * const allowed = await kavach.org?.hasPermission(org.id, userId, 'agents:create');
		 * ```
		 */
		org: orgModule,
		/**
		 * SSO (SAML 2.0 + OIDC) enterprise authentication.
		 *
		 * Null when `sso` config was not provided.
		 *
		 * @example
		 * ```typescript
		 * const conn = await kavach.sso?.createConnection({ orgId, providerId: 'okta', type: 'saml', domain: 'acme.com' });
		 * const url = await kavach.sso?.getSamlAuthUrl(conn.id);
		 * ```
		 */
		sso: ssoModule,
		/**
		 * Admin module.
		 *
		 * Null when `admin` config was not provided.
		 *
		 * @example
		 * ```typescript
		 * await kavach.admin?.banUser(userId, 'Spam');
		 * const { session } = await kavach.admin?.impersonate(adminId, userId);
		 * ```
		 */
		admin: adminModule,
		/**
		 * API key management.
		 *
		 * Null when `apiKeys` config was not provided.
		 *
		 * @example
		 * ```typescript
		 * const { key, apiKey } = await kavach.apiKeys?.create({ userId, name: 'CI', permissions: ['agents:read'] });
		 * const result = await kavach.apiKeys?.validate(key);
		 * ```
		 */
		apiKeys: apiKeyManagerModule,
		/**
		 * Username + password authentication.
		 *
		 * Null when `username` config was not provided or `auth.session` is not
		 * configured (sessions are required to issue tokens on sign-in/up).
		 *
		 * @example
		 * ```typescript
		 * const response = await kavach.username?.handleRequest(request);
		 * if (response) return response;
		 * ```
		 */
		username: usernameModule,
		/**
		 * Password reset (forgot password + reset password).
		 *
		 * Null when `passwordReset` config was not provided or `auth.session`
		 * is not configured.
		 *
		 * @example
		 * ```typescript
		 * // In your route handler
		 * const response = await kavach.passwordReset?.handleRequest(request);
		 * if (response) return response;
		 *
		 * // Or programmatically
		 * await kavach.passwordReset?.requestReset('alice@example.com');
		 * await kavach.passwordReset?.resetPassword(token, 'new-password');
		 * ```
		 */
		passwordReset: passwordResetModule,
		/**
		 * Email address verification.
		 *
		 * Null when `emailVerification` config was not provided.
		 *
		 * @example
		 * ```typescript
		 * // Send a verification email after sign-up
		 * await kavach.emailVerification?.sendVerification(userId, email);
		 *
		 * // Confirm from the link in the email
		 * const result = await kavach.emailVerification?.verify(token);
		 *
		 * // Check status
		 * const verified = await kavach.emailVerification?.isVerified(userId);
		 * ```
		 */
		emailVerification: emailVerificationModule,
		/**
		 * One-time tokens (email verify, password reset, invitations, custom).
		 *
		 * Always available. Used internally by password reset but exposed for
		 * custom flows (email verification, invitation links, etc.).
		 */
		oneTimeTokens: oneTimeTokenModule,
		/**
		 * Session freshness enforcement for sensitive operations.
		 *
		 * Use as middleware before password changes, passkey registration,
		 * billing updates, or any action that requires a recently-authenticated
		 * session rather than an auto-refreshed one.
		 *
		 * @example
		 * ```typescript
		 * const stale = kavach.sessionFreshness.guard(session);
		 * if (stale) return stale; // 403 SESSION_NOT_FRESH
		 * ```
		 */
		sessionFreshness: createSessionFreshnessModule(
			config.sessionFreshness,
		) as SessionFreshnessModule,
		/**
		 * Phone number (SMS OTP) authentication.
		 *
		 * Null when `phone` config was not provided or `auth.session` is not
		 * configured.
		 *
		 * @example
		 * ```typescript
		 * const response = await kavach.phone?.handleRequest(request);
		 * if (response) return response;
		 * ```
		 */
		phone: phoneModule,
		/**
		 * Captcha integration (reCAPTCHA, hCaptcha, Cloudflare Turnstile).
		 *
		 * Null when `captcha` config was not provided.
		 *
		 * @example
		 * ```typescript
		 * const result = await kavach.captcha?.verify(token, ip);
		 * if (!result?.success) return new Response('Captcha failed', { status: 403 });
		 * ```
		 */
		captcha: captchaModule,
		/**
		 * Webhook system.
		 *
		 * Null when `webhooks` config was not provided or the array is empty.
		 *
		 * @example
		 * ```typescript
		 * kavach.webhooks?.emit('user.created', { userId: user.id });
		 * ```
		 */
		webhooks: webhookModule,
		/**
		 * Redirect chain manager.
		 *
		 * Capture the user's original destination before auth redirects, push
		 * intermediate steps (onboarding, email verification), and pop them
		 * back in order. Cookie-based, works across page transitions and tabs.
		 *
		 * @example
		 * ```typescript
		 * // In auth middleware — save where the user was going
		 * const setCookie = kavach.redirects.capture(request);
		 * return new Response(null, { status: 302, headers: { Location: '/sign-in', 'Set-Cookie': setCookie } });
		 *
		 * // After sign-in — send user to their original destination
		 * const { url, clearCookie } = kavach.redirects.pop(request);
		 * const headers: Record<string, string> = { Location: url };
		 * if (clearCookie) headers['Set-Cookie'] = clearCookie;
		 * return new Response(null, { status: 302, headers });
		 * ```
		 */
		redirects: redirectChain,
		/**
		 * Unified policy engine.
		 *
		 * Single decision point that combines RBAC role expansion, ABAC constraint
		 * evaluation, and ReBAC graph queries. Backed by a process-local LRU cache
		 * with deterministic invalidation.
		 *
		 * @example
		 * ```typescript
		 * const decision = await kavach.policy.evaluate({
		 *   subject: { agentId: 'agent-abc' },
		 *   action: 'read',
		 *   resource: 'tool:github:list_issues',
		 * });
		 * if (!decision.allowed) throw new Error(decision.reason);
		 *
		 * // Flush cached decisions after a permission change
		 * kavach.policy.invalidate({ agentId: 'agent-abc' });
		 *
		 * // Inspect cache health
		 * const { hits, misses, size, evictions } = kavach.policy.stats();
		 * ```
		 */
		policy: {
			evaluate: policyEngine.evaluate,
			invalidate: policyEngine.invalidate,
			stats: policyEngine.stats,
		},
		/**
		 * Plugin system.
		 *
		 * Route incoming HTTP requests through plugin-registered endpoints,
		 * retrieve all endpoints for adapter mounting, or access plugin-provided
		 * context values.
		 *
		 * @example
		 * ```typescript
		 * // In a framework adapter
		 * app.all('/kavach/*', async (req) => {
		 *   const response = await kavach.plugins.handleRequest(req);
		 *   if (response) return response;
		 *   return new Response('Not Found', { status: 404 });
		 * });
		 * ```
		 */
		plugins: {
			/** Route a request through plugin endpoints. Returns null if no plugin handles it. */
			handleRequest(request: Request, basePath = ""): Promise<Response | null> {
				return pluginRouter.handle(request, basePath, endpointCtx);
			},
			/** Get all endpoints registered by plugins (for framework adapter mounting). */
			getEndpoints() {
				return pluginRouter.getEndpoints();
			},
			/** Get the merged plugin context (values returned from plugin init). */
			getContext(): Record<string, unknown> {
				return { ...pluginRegistry.pluginContext };
			},
			/** Access the raw plugin registry (hooks, migrations, etc.). */
			registry: pluginRegistry,
		},
	};
}

export type TheAuth = Awaited<ReturnType<typeof createTheAuth>>;

/**
 * @deprecated Use `createTheAuth` instead. Will be removed in a future major version.
 */
export const createAuth = createTheAuth;

/**
 * @deprecated Use `createTheAuth` instead. Will be removed in a future major version.
 */
export const createKavach = createTheAuth;

/**
 * @deprecated Use `TheAuth` instead. Will be removed in a future major version.
 */
export type Auth = TheAuth;

/**
 * @deprecated Use `TheAuth` instead. Will be removed in a future major version.
 */
export type Kavach = TheAuth;
