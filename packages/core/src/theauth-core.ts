import { eq } from "drizzle-orm";
import { createAgentModule } from "./agent/agent.js";
import { createPrivilegeAnalyzer } from "./analyzer/privilege.js";
import { createApprovalModule } from "./approval/approval.js";
import { createAuditModule } from "./audit/audit.js";
import { enableAuditChain } from "./audit/chain.js";
import { setAuditWriteErrorHandler } from "./audit/record.js";
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
import type { SignInGate } from "./auth/sign-in-gate.js";
import { createSignInGate } from "./auth/sign-in-gate.js";
import { signInGatePlugin } from "./auth/sign-in-gate-plugin.js";
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
import type { Database } from "./db/database.js";
import { createTables } from "./db/migrations.js";
import { mcpServers, users } from "./db/schema.js";
import { createDelegationModule } from "./delegation/delegation.js";
import { createDidModule } from "./did/module.js";
import type { ViolationType } from "./hooks/lifecycle.js";
import { createPermissionEngine } from "./permission/engine.js";
import { buildClearCookie, extractToken, json } from "./plugin/helpers.js";
import { createPluginRouter } from "./plugin/router.js";
import { initializePlugins } from "./plugin/runner.js";
import type { EndpointContext, TheAuthPlugin } from "./plugin/types.js";
import { createPolicyModule } from "./policies/budget.js";
import { createPolicyEngine } from "./policy/engine.js";
import type { PolicyEngine } from "./policy/types.js";
import type { RedirectChainManager } from "./redirect/chain.js";
import { createRedirectChain } from "./redirect/chain.js";
import type { SessionFreshnessModule } from "./session/freshness.js";
import { createSessionFreshnessModule } from "./session/freshness.js";
import type { SessionManager } from "./session/session.js";
import { createSessionManager } from "./session/session.js";
import { assertSecondaryStorageConfig, createSecondaryStorageResolver } from "./storage/resolve.js";
import { createTenantModule } from "./tenant/tenant.js";
import { createTrustModule } from "./trust/scoring.js";
import type {
	AuditExportOptions,
	AuditFilter,
	AuthorizeRequest,
	AuthorizeResult,
	DelegateInput,
	DelegationChain,
	McpServer,
	McpServerInput,
	RequestContext,
	TheAuthConfig,
} from "./types.js";

/** Maps a denial reason string to a violation type, defaulting to `permission_denied`. */
function classifyViolation(reason: string | undefined): ViolationType {
	const r = reason?.toLowerCase() ?? "";
	if (r.includes("rate") || r.includes("rate_limited")) return "rate_limited";
	if (r.includes("ip") || r.includes("allowlist")) return "ip_blocked";
	if (r.includes("time") || r.includes("window")) return "time_restricted";
	if (r.includes("approval")) return "approval_required";
	return "permission_denied";
}

/** Append the sign-in gate routes unless the caller already registered them. */
function withSignInGatePlugin(plugins: TheAuthPlugin[], hasSession: boolean): TheAuthPlugin[] {
	if (!hasSession || plugins.some((p) => p.id === "theauth-sign-in-gate")) return plugins;
	return [...plugins, signInGatePlugin()];
}

/** Opens the database for a config. Injected so entry points choose which drivers can load. */
export type DatabaseOpener = (config: TheAuthConfig["database"]) => Promise<Database>;

export async function createTheAuthWith(config: TheAuthConfig, openDatabase: DatabaseOpener) {
	const authAdapter = config.auth?.adapter ?? null;

	const db = await openDatabase(config.database);

	// CREATE TABLE IF NOT EXISTS keeps this safe on every startup.
	if (!config.database.skipMigrations) {
		await createTables(db, config.database.provider, config);
	}

	// The policy engine can open approval requests, so the approval module is created first.
	const approvalModule = createApprovalModule(config.approval ?? {}, db);
	const policyEngine: PolicyEngine = createPolicyEngine({
		db,
		config: config.policy,
		approval: approvalModule,
	});

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

	if (config.audit?.tamperEvident) {
		enableAuditChain(db, { hmacKey: config.audit.hmacKey });
	}
	setAuditWriteErrorHandler(db, config.audit?.onAuditError);
	const auditModule = createAuditModule({ db, hmacKey: config.audit?.hmacKey });

	const delegationModule = createDelegationModule({ db });

	const sessionManager: SessionManager | null = config.auth?.session
		? createSessionManager(config.auth.session, db)
		: null;

	// Always created. Without config, only the forced password change is active.
	// It reads only tables whose feature is enabled, mirroring createTables feature detection.
	const signInGate: SignInGate = createSignInGate({
		db,
		config: config.signInGate,
		sessionSecret: config.auth?.session?.secret,
		totpAvailable: !!config.totp || (config.plugins?.some((p) => p.id === "theauth-2fa") ?? false),
		usernameAccountsAvailable: !!config.username,
	});

	const privilegeAnalyzer = createPrivilegeAnalyzer(db);

	const hooks = config.hooks ?? {};

	const tenantModule = createTenantModule(db);

	const policyModule = createPolicyModule(db);

	const trustModule = createTrustModule({}, db);

	const didModule = createDidModule(db, config.did);

	const magicLinkModule: MagicLinkModule | null =
		config.magicLink && sessionManager
			? createMagicLinkModule(config.magicLink, db, sessionManager, signInGate)
			: null;

	const emailOtpModule: EmailOtpModule | null =
		config.emailOtp && sessionManager
			? createEmailOtpModule(config.emailOtp, db, sessionManager, signInGate)
			: null;

	const totpModule: TotpModule | null = config.totp ? createTotpModule(config.totp, db) : null;

	const passkeyModule: PasskeyModule | null = config.passkey
		? createPasskeyModule(config.passkey, db)
		: null;

	const orgModule: OrgModule | null = config.org ? createOrgModule(config.org, db) : null;

	const ssoModule: SsoModule | null = config.sso ? createSsoModule(config.sso, db) : null;

	const adminModule: AdminModule | null = config.admin
		? createAdminModule(config.admin, db, sessionManager)
		: null;

	const apiKeyManagerModule: ApiKeyManagerModule | null = config.apiKeys
		? createApiKeyManagerModule(config.apiKeys, db)
		: null;

	const usernameModule: UsernameAuthModule | null =
		config.username && sessionManager
			? createUsernameAuthModule(config.username, db, sessionManager, signInGate)
			: null;

	const oneTimeTokenModule = createOneTimeTokenModule({}, db);
	const passwordResetModule: PasswordResetModule | null =
		config.passwordReset && sessionManager
			? createPasswordResetModule(
					config.passwordReset,
					db,
					sessionManager,
					oneTimeTokenModule,
					signInGate,
				)
			: null;

	const emailVerificationModule: EmailVerificationModule | null = config.emailVerification
		? createEmailVerificationModule(config.emailVerification, db, oneTimeTokenModule)
		: null;

	const phoneModule: PhoneAuthModule | null =
		config.phone && sessionManager
			? createPhoneAuthModule(config.phone, db, sessionManager, signInGate)
			: null;

	const captchaModule: CaptchaModule | null = config.captcha
		? createCaptchaModule(config.captcha)
		: null;

	const redirectChain: RedirectChainManager = createRedirectChain(config.redirects);

	const webhookModule: WebhookModule | null =
		config.webhooks && config.webhooks.length > 0 ? createWebhookModule(config.webhooks) : null;

	// Runs after core modules so plugins can depend on them.
	assertSecondaryStorageConfig(config.secondaryStorage);
	const secondaryStorage = createSecondaryStorageResolver(config.secondaryStorage, db);
	const pluginRegistry = await initializePlugins(
		withSignInGatePlugin(config.plugins ?? [], sessionManager !== null),
		db,
		config,
		sessionManager,
		secondaryStorage,
		signInGate,
	);

	const endpointCtx: EndpointContext = {
		db,
		trustedProxy: config.trustedProxy,
		async getUser(request: Request): Promise<ResolvedUser | null> {
			if (authAdapter) {
				const user = await authAdapter.resolveUser(request);
				if (user) return user;
			}

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

	async function runRequestHooks(request: Request): Promise<Request | Response> {
		let current = request;
		for (const hook of pluginRegistry.hooks.onRequest) {
			if (!hook) continue;
			const result = await hook(current);
			if (result instanceof Response) return result;
			if (result instanceof Request) current = result;
		}
		return current;
	}

	const pluginRouter = createPluginRouter(pluginRegistry.endpoints, {
		trustedProxy: config.trustedProxy,
	});

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
					// Invalid token: still clear the cookie.
				}

				return new Response(JSON.stringify({ success: true }), {
					status: 200,
					headers: {
						"Content-Type": "application/json",
						"Set-Cookie": buildClearCookie("theauth_session"),
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

	async function authorize(
		agentId: string,
		request: AuthorizeRequest,
		context?: RequestContext,
	): Promise<AuthorizeResult> {
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
			const auditId = await permissionEngine.recordDenial(
				{ agentId: agent.id, ownerId: agent.ownerId },
				context ? { ...request, context } : request,
				agent.status === "expired" ? "agent_expired" : "agent_revoked",
			);
			return {
				allowed: false,
				reason: `Agent "${agent.name}" is ${agent.status}`,
				auditId,
			};
		}

		const enrichedRequest: AuthorizeRequest = context ? { ...request, context } : request;

		// Denial rows are deferred: a delegated fallback may overturn this denial,
		// and writing one row per path would orphan the first auditId.
		const ownResult = await permissionEngine.authorize(agent, enrichedRequest, {
			deferDenialAudit: true,
		});

		let finalResult: AuthorizeResult;

		if (ownResult.allowed) {
			finalResult = ownResult;
		} else {
			const delegatedPerms = await delegationModule.getEffectivePermissions(agentId);

			if (delegatedPerms.length === 0) {
				finalResult = ownResult;
			} else {
				const agentWithDelegated = { ...agent, permissions: delegatedPerms };
				const delegatedResult = await permissionEngine.authorize(
					agentWithDelegated,
					enrichedRequest,
					{ deferDenialAudit: true },
				);
				// Both denied: keep the original denial, unless an approval failure is more specific.
				const approvalDenied = delegatedResult.reason?.startsWith("APPROVAL_") === true;
				finalResult = delegatedResult.allowed || approvalDenied ? delegatedResult : ownResult;
			}
		}

		// One row for the final denial; allowed results were already written.
		if (!finalResult.allowed) {
			await permissionEngine.auditDenial(agent, enrichedRequest, finalResult);
		}

		// Fire-and-forget: a throwing hook must not change the authorization result.
		void Promise.resolve()
			.then(() =>
				hooks.afterAuthorize?.({
					agentId,
					action: request.action,
					resource: request.resource,
					result: {
						allowed: finalResult.allowed,
						reason: finalResult.reason,
						auditId: finalResult.auditId,
					},
				}),
			)
			.catch(() => {
				// Hook failures are the caller's concern; the SDK has no logger to report to.
			});

		if (!finalResult.allowed) {
			void Promise.resolve()
				.then(() =>
					hooks.onViolation?.({
						type: classifyViolation(finalResult.reason),
						agentId,
						action: request.action,
						resource: request.resource,
						reason: finalResult.reason ?? "Authorization denied",
					}),
				)
				.catch(() => {});
		}

		return finalResult;
	}

	async function authorizeByToken(
		token: string,
		request: AuthorizeRequest,
		context?: RequestContext,
	): Promise<AuthorizeResult> {
		const { agent, rejected } = await agentModule.resolveToken(token);
		if (!agent) {
			// A token that belongs to a known revoked or expired agent is recorded.
			// An unknown token has no agent to attach a row to and is not.
			const auditId = rejected
				? await permissionEngine.recordDenial(
						rejected,
						context ? { ...request, context } : request,
						rejected.reason === "expired" ? "agent_expired" : "agent_revoked",
					)
				: "";
			return {
				allowed: false,
				reason: "Invalid or expired agent token",
				auditId,
			};
		}
		const enrichedRequest: AuthorizeRequest = context ? { ...request, context } : request;
		return permissionEngine.authorize(agent, enrichedRequest);
	}

	async function delegate(input: DelegateInput): Promise<DelegationChain> {
		const parentAgent = await agentModule.get(input.fromAgent);
		if (!parentAgent) throw new Error(`Parent agent "${input.fromAgent}" not found`);
		if (parentAgent.status !== "active") {
			throw new Error(`Parent agent "${parentAgent.name}" is ${parentAgent.status}`);
		}
		return delegationModule.delegate(input);
	}

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
			const result = await agentModule.revoke(agentId);
			// Vault consents tied to the cascaded chains die with them.
			const vault = pluginRegistry.pluginContext.tokenVault as
				| { revokeForDelegation?: (id: string) => Promise<number> }
				| undefined;
			for (const chainId of result.revokedDelegations) {
				await vault?.revokeForDelegation?.(chainId);
			}
			void hooks.onAgentRevoke?.(agentId);
			return result;
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

	// Backed by the theauth_mcp_servers table (defined in db/schema.ts).
	const mcpRegistry = {
		/** Registers an MCP tool server. The returned record includes the generated `id` and `createdAt`. */
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

		/** Lists all registered MCP servers, active or not. */
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

		/** Gets one MCP server by ID, or null when not found. */
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
			revoke: async (chainId: string): Promise<void> => {
				await delegationModule.revokeDelegation(chainId);
				// Vault consents tied to this chain die with it (reads also re-check the chain).
				const vault = pluginRegistry.pluginContext.tokenVault as
					| { revokeForDelegation?: (id: string) => Promise<number> }
					| undefined;
				await vault?.revokeForDelegation?.(chainId);
			},
			getEffectivePermissions: delegationModule.getEffectivePermissions,
			listChains: delegationModule.listChains,
		},
		audit: {
			query: (filter: AuditFilter) => auditModule.query(filter),
			export: (options: AuditExportOptions) => auditModule.export(options),
			cleanup: (options: { retentionDays: number }) => auditModule.cleanup(options),
			replayAgent: (agentId: string, opts?: Parameters<typeof auditModule.replayAgent>[1]) =>
				auditModule.replayAgent(agentId, opts),
		},
		/** MCP server registration, backed by the `theauth_mcp_servers` table. */
		mcp: mcpRegistry,
		/** Per-feature secondary storage (rate limits, device codes, ...). */
		secondaryStorage,
		/** Least-privilege analyzer: compares granted permissions against audit log usage. */
		analyzer: {
			analyzeAgent: privilegeAnalyzer.analyzeAgent,
			analyzeAll: privilegeAnalyzer.analyzeAll,
			getSummary: privilegeAnalyzer.getSummary,
		},
		/**
		 * Human auth integration. `session` is only available when `auth.session` was passed to `createTheAuth()`.
		 *
		 * @example
		 * ```typescript
		 * app.use(async (req, res, next) => {
		 *   const user = await theauth.auth.resolveUser(req);
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
		/** @deprecated Use `theauth.auth.resolveUser(request)` instead. */
		async resolveUser(request: Request): Promise<ResolvedUser | null> {
			if (!authAdapter) return null;
			return authAdapter.resolveUser(request);
		},
		db,
		/** Multi-tenant isolation: tenants (organizations) share one instance with isolated data. */
		tenant: tenantModule,
		/** Per-agent, per-user or per-tenant spending caps. Exceeded policies warn, throttle, block or revoke. */
		policies: policyModule,
		/** Async human approval flows (CIBA-style): create requests, notify humans, approve or deny. */
		approval: approvalModule,
		/** Graduated autonomy trust scores (0-100) derived from audit history. */
		trust: trustModule,
		/**
		 * W3C Decentralized Identifiers for agents. Private keys are returned on generation and never stored.
		 *
		 * @example
		 * ```typescript
		 * const { agentDid, privateKeyJwk } = await theauth.did.generateKey(agentId);
		 * const signed = await theauth.did.sign(agentId, { action: 'read' }, privateKeyJwk);
		 * const result = await theauth.did.verify(signed.jws, agentDid.did);
		 * ```
		 */
		did: didModule,
		/**
		 * Magic link authentication. Null unless `magicLink` and `auth.session` are configured.
		 *
		 * @example
		 * ```typescript
		 * // In your route handler
		 * const response = await theauth.magicLink?.handleRequest(request);
		 * if (response) return response;
		 * ```
		 */
		magicLink: magicLinkModule,
		/**
		 * Email OTP authentication. Null unless `emailOtp` and `auth.session` are configured.
		 *
		 * @example
		 * ```typescript
		 * const response = await theauth.emailOtp?.handleRequest(request);
		 * if (response) return response;
		 * ```
		 */
		emailOtp: emailOtpModule,
		/**
		 * TOTP two-factor authentication. Null unless `totp` is configured.
		 *
		 * @example
		 * ```typescript
		 * // On setup (show QR code to user)
		 * const { secret, uri, backupCodes } = await theauth.totp.setup(userId);
		 *
		 * // After user scans QR and enters code
		 * const { enabled } = await theauth.totp.enable(userId, totpCode);
		 *
		 * // On login (after password check)
		 * const { valid } = await theauth.totp.verify(userId, totpCode);
		 * ```
		 */
		totp: totpModule,
		/**
		 * Passkey (WebAuthn) authentication. Null unless `passkey` is configured.
		 *
		 * @example
		 * ```typescript
		 * // Registration, step 1: get options, send to browser
		 * const options = await theauth.passkey.getRegistrationOptions(userId, userName);
		 *
		 * // Registration, step 2: verify browser response
		 * const { credential } = await theauth.passkey.verifyRegistration(userId, response);
		 *
		 * // Authentication, step 1: get options
		 * const options = await theauth.passkey.getAuthenticationOptions(userId);
		 *
		 * // Authentication, step 2: verify browser response
		 * const result = await theauth.passkey.verifyAuthentication(response);
		 * if (result) console.log('Authenticated user:', result.userId);
		 * ```
		 */
		passkey: passkeyModule,
		/**
		 * Organizations and RBAC. Null unless `org` is configured.
		 *
		 * @example
		 * ```typescript
		 * const org = await theauth.org?.create({ name: 'Acme', slug: 'acme', ownerId: userId });
		 * const allowed = await theauth.org?.hasPermission(org.id, userId, 'agents:create');
		 * ```
		 */
		org: orgModule,
		/**
		 * SSO (SAML 2.0 and OIDC) enterprise authentication. Null unless `sso` is configured.
		 *
		 * @example
		 * ```typescript
		 * const conn = await theauth.sso?.createConnection({ orgId, providerId: 'okta', type: 'saml', domain: 'acme.com' });
		 * const url = await theauth.sso?.getSamlAuthUrl(conn.id);
		 * ```
		 */
		sso: ssoModule,
		/**
		 * Admin module. Null unless `admin` is configured.
		 *
		 * @example
		 * ```typescript
		 * await theauth.admin?.banUser(userId, 'Spam');
		 * const { session } = await theauth.admin?.impersonate(adminId, userId);
		 * ```
		 */
		admin: adminModule,
		/**
		 * API key management. Null unless `apiKeys` is configured.
		 *
		 * @example
		 * ```typescript
		 * const { key, apiKey } = await theauth.apiKeys?.create({ userId, name: 'CI', permissions: ['agents:read'] });
		 * const result = await theauth.apiKeys?.validate(key);
		 * ```
		 */
		apiKeys: apiKeyManagerModule,
		/**
		 * Username and password authentication. Null unless `username` and `auth.session` are configured.
		 *
		 * @example
		 * ```typescript
		 * const response = await theauth.username?.handleRequest(request);
		 * if (response) return response;
		 * ```
		 */
		username: usernameModule,
		/**
		 * Password reset. Null unless `passwordReset` and `auth.session` are configured.
		 *
		 * @example
		 * ```typescript
		 * // In your route handler
		 * const response = await theauth.passwordReset?.handleRequest(request);
		 * if (response) return response;
		 *
		 * // Or programmatically
		 * await theauth.passwordReset?.requestReset('alice@example.com');
		 * await theauth.passwordReset?.resetPassword(token, 'new-password');
		 * ```
		 */
		passwordReset: passwordResetModule,
		/**
		 * Email address verification. Null unless `emailVerification` is configured.
		 *
		 * @example
		 * ```typescript
		 * // Send a verification email after sign-up
		 * await theauth.emailVerification?.sendVerification(userId, email);
		 *
		 * // Confirm from the link in the email
		 * const result = await theauth.emailVerification?.verify(token);
		 *
		 * // Check status
		 * const verified = await theauth.emailVerification?.isVerified(userId);
		 * ```
		 */
		emailVerification: emailVerificationModule,
		/** One-time tokens for email verification, password reset, invitations and custom flows. */
		oneTimeTokens: oneTimeTokenModule,
		/**
		 * Session freshness guard for sensitive operations that need a recent login, not an auto-refreshed session.
		 *
		 * @example
		 * ```typescript
		 * const stale = theauth.sessionFreshness.guard(session);
		 * if (stale) return stale; // 403 SESSION_NOT_FRESH
		 * ```
		 */
		sessionFreshness: createSessionFreshnessModule(
			config.sessionFreshness,
		) as SessionFreshnessModule,
		/**
		 * Phone (SMS OTP) authentication. Null unless `phone` and `auth.session` are configured.
		 *
		 * @example
		 * ```typescript
		 * const response = await theauth.phone?.handleRequest(request);
		 * if (response) return response;
		 * ```
		 */
		phone: phoneModule,
		/**
		 * Captcha (reCAPTCHA, hCaptcha, Turnstile). Null unless `captcha` is configured.
		 *
		 * @example
		 * ```typescript
		 * const result = await theauth.captcha?.verify(token, ip);
		 * if (!result?.success) return new Response('Captcha failed', { status: 403 });
		 * ```
		 */
		captcha: captchaModule,
		/**
		 * Webhooks. Null unless `webhooks` has at least one entry.
		 *
		 * @example
		 * ```typescript
		 * theauth.webhooks?.emit('user.created', { userId: user.id });
		 * ```
		 */
		webhooks: webhookModule,
		/**
		 * Redirect chain for returning users to their original destination after auth steps. Cookie-based.
		 *
		 * @example
		 * ```typescript
		 * // In auth middleware, save where the user was going
		 * const setCookie = theauth.redirects.capture(request);
		 * return new Response(null, { status: 302, headers: { Location: '/sign-in', 'Set-Cookie': setCookie } });
		 *
		 * // After sign-in, send user to their original destination
		 * const { url, clearCookie } = theauth.redirects.pop(request);
		 * const headers: Record<string, string> = { Location: url };
		 * if (clearCookie) headers['Set-Cookie'] = clearCookie;
		 * return new Response(null, { status: 302, headers });
		 * ```
		 */
		redirects: redirectChain,
		/**
		 * Unified policy engine (RBAC, ABAC and ReBAC) with a process-local LRU cache and deterministic invalidation.
		 *
		 * @example
		 * ```typescript
		 * const decision = await theauth.policy.evaluate({
		 *   subject: { agentId: 'agent-abc' },
		 *   action: 'read',
		 *   resource: 'tool:github:list_issues',
		 * });
		 * if (!decision.allowed) throw new Error(decision.reason);
		 *
		 * // Flush cached decisions after a permission change
		 * theauth.policy.invalidate({ agentId: 'agent-abc' });
		 *
		 * // Inspect cache health
		 * const { hits, misses, size, evictions } = theauth.policy.stats();
		 * ```
		 */
		policy: {
			evaluate: policyEngine.evaluate,
			invalidate: policyEngine.invalidate,
			stats: policyEngine.stats,
		},
		/**
		 * Plugin system: route requests through plugin endpoints and read plugin context.
		 *
		 * @example
		 * ```typescript
		 * // In a framework adapter
		 * app.all('/theauth/*', async (req) => {
		 *   const response = await theauth.plugins.handleRequest(req);
		 *   if (response) return response;
		 *   return new Response('Not Found', { status: 404 });
		 * });
		 * ```
		 */
		plugins: {
			/** Route a request through plugin endpoints. Returns null if no plugin handles it. */
			async handleRequest(request: Request, basePath = ""): Promise<Response | null> {
				const hooked = await runRequestHooks(request);
				if (hooked instanceof Response) return hooked;
				return pluginRouter.handle(hooked, basePath, endpointCtx);
			},
			/** Runs plugin `onRequest` hooks for requests TheAuth does not route itself, such as `/mcp/token`. */
			runRequestHooks,
			getEndpoints() {
				return pluginRouter.getEndpoints();
			},
			getContext(): Record<string, unknown> {
				return { ...pluginRegistry.pluginContext };
			},
			registry: pluginRegistry,
		},
	};
}

export type TheAuth = Awaited<ReturnType<typeof createTheAuthWith>>;
